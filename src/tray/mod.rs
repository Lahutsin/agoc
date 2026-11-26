/// tao + tray-icon event loop (macOS menu bar, Windows notification area).
#[cfg(any(target_os = "macos", windows))]
mod desktop;
#[cfg(target_os = "linux")]
mod linux;

use crate::control::{self, Message};
use crate::network::NetworkOptions;
use anyhow::{bail, Context, Result};
use clap::Parser;
#[cfg(unix)]
use std::fs::File;
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader},
    path::Path,
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    thread,
    time::{Duration, Instant},
};
#[cfg(unix)]
use std::{
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
        net::UnixListener,
    },
    process::{Command, Stdio},
};

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Outbound AI-network firewall control for sensitive software environments in the system tray"
)]
pub struct Options {
    /// Use the restricted passwordless helper installed by install-autostart.sh.
    #[arg(long, conflicts_with_all = ["state", "direct_interface", "interval", "domain"])]
    installed_helper: bool,
    #[command(flatten)]
    network: NetworkOptions,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=10))]
    interval: u64,
    #[arg(long)]
    domain: Vec<String>,
}

#[derive(Debug)]
enum Event {
    Status(Message),
    Finished,
    Failed(String),
    Quit,
    #[cfg(any(target_os = "macos", windows))]
    Refresh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Color {
    Waiting,
    /// The app itself failed (helper, authorization, monitor): nothing works.
    Error,
    Blocked,
    Allowed,
    Partial,
}

struct View {
    label: String,
    details: [String; 3],
    color: Color,
    quitting: bool,
    failed: bool,
}

impl Default for View {
    fn default() -> Self {
        Self {
            label: "Starting; waiting for administrator authorization...".into(),
            details: [
                "IPv4: checking...".into(),
                "IPv6: checking...".into(),
                "Direct interface: detecting...".into(),
            ],
            color: Color::Waiting,
            quitting: false,
            failed: false,
        }
    }
}

impl View {
    fn event(&mut self, event: Event, worker: &Worker) -> Result<bool> {
        match event {
            Event::Status(Message::Status {
                allow4,
                allow6,
                addresses,
                network,
            }) if !self.quitting => {
                let allow4 = allow4 && network.ipv4.changed();
                let allow6 = allow6 && network.ipv6.changed();
                self.label = if allow4 || allow6 {
                    let family = match (allow4, allow6) { (true, true) => "IPv4 + IPv6", (true, false) => "IPv4", _ => "IPv6" };
                    format!("AI OPEN ({family}, {addresses} IPs)")
                } else if network.error.is_some() {
                    if network.ipv4.original.is_none() && network.ipv6.original.is_none() {
                        "Original IP unknown - AI CLOSE".into()
                    } else {
                        "Network check failed - AI CLOSE".into()
                    }
                } else if [&network.ipv4, &network.ipv6].iter().any(|family| {
                    matches!((family.original, family.current), (Some(a), Some(b)) if a == b)
                }) {
                    "IP unchanged - AI CLOSE".into()
                } else if network.ipv4.original.is_none() || network.ipv6.original.is_none() {
                    "Original IP unknown - AI CLOSE".into()
                } else if network.ipv4.current.is_none() || network.ipv6.current.is_none() {
                    "Current IP unknown - AI CLOSE".into()
                } else {
                    "IP unchanged - AI CLOSE".into()
                };
                self.details = [
                    family_row(&network.ipv4, "IPv4", allow4),
                    family_row(&network.ipv6, "IPv6", allow6),
                    fit(&network.error.as_deref().map_or_else(
                        || {
                            network.interface.as_ref().map_or_else(
                                || {
                                    if network.ipv4.original.is_some()
                                        || network.ipv6.original.is_some()
                                    {
                                        "Original source: saved baseline".into()
                                    } else {
                                        "Direct interface: detecting...".into()
                                    }
                                },
                                |name| format!("Direct interface: {name}"),
                            )
                        },
                        |error| format!("Check failed: {}", reason(error)),
                    )),
                ];
                self.label = fit(&self.label);
                // No public IPv6 on the current route: all traffic leaves over IPv4,
                // so a changed IPv4 alone is enough for green. IPv6 stays blocked in
                // the firewall regardless (allow6 is not touched here).
                let ipv6_unused = network.ipv6.current.is_none();
                self.color = match (allow4, allow6) {
                    (true, true) => Color::Allowed,
                    (true, false) if ipv6_unused => Color::Allowed,
                    (false, false) => Color::Blocked,
                    _ => Color::Partial,
                };
            }
            Event::Status(Message::Failure { message }) | Event::Failed(message) => {
                eprintln!("ERROR: {message}");
                self.label = fit(&format!("Error: {}", reason(&message)));
                self.details[2] = "Rules may remain; see README".into();
                self.color = Color::Error;
                self.failed = true;
                self.quitting = false;
            }
            Event::Quit if self.failed => return Ok(true),
            Event::Quit if !self.quitting => {
                worker.quit()?;
                self.label = "Stopping and removing firewall rules...".into();
                self.quitting = true;
            }
            Event::Finished => return Ok(true),
            _ => {}
        }
        Ok(false)
    }
}

/// Longest menu row, in characters. Full errors go to stderr (see the monitor log);
/// the menu only shows a short reason so it stays a sane width.
const MENU_WIDTH: usize = 60;

/// Cut text to `MENU_WIDTH` characters, ending with an ellipsis when shortened.
fn fit(text: &str) -> String {
    if text.chars().count() <= MENU_WIDTH {
        return text.into();
    }
    let mut short: String = text.chars().take(MENU_WIDTH - 1).collect();
    short.push('…');
    short
}

/// Root cause of the first error in an anyhow `{:#}` chain (`"a: b: root; c: d"`),
/// without the `(os error N)` suffix.
fn reason(error: &str) -> &str {
    let first = error.split("; ").next().unwrap_or(error);
    let root = first.rsplit(": ").next().unwrap_or(first).trim();
    match root.rfind(" (os error ") {
        Some(index) if root.ends_with(')') => &root[..index],
        _ => root,
    }
}

/// Long IPv6 addresses keep the first three groups and the last one.
fn short_ip(ip: std::net::IpAddr) -> String {
    let text = ip.to_string();
    if text.len() <= 21 {
        return text;
    }
    let groups: Vec<&str> = text.split(':').collect();
    format!("{}:…:{}", groups[..3].join(":"), groups[groups.len() - 1])
}

/// One compact menu row per address family, e.g. `IPv4 ALLOWED: 1.2.3.4 → 5.6.7.8`.
fn family_row(family: &crate::network::FamilyStatus, name: &str, allowed: bool) -> String {
    let state = match (family.original, family.current) {
        (Some(original), Some(current)) if original == current => {
            format!("unchanged {}", short_ip(original))
        }
        (Some(original), Some(current)) => {
            format!("{} → {}", short_ip(original), short_ip(current))
        }
        (None, _) => "original unknown".into(),
        (Some(_), None) => "unavailable".into(),
    };
    let verdict = if allowed { "ALLOWED" } else { "BLOCKED" };
    fit(&match &family.error {
        Some(error) => format!("{name} {verdict}: {state} ({})", reason(error)),
        None => format!("{name} {verdict}: {state}"),
    })
}

/// Pre-rendered, pixel-hinted tray artwork from `icon/gen_icon.py`, per size:
/// the frame (rounded square, without the globe) and the globe coverage mask.
/// Each size is used as-is: resampling one big image at runtime is what made small
/// tray icons blurry. Linux hosts pick the closest size for their panel and scale;
/// macOS uses 36 px and Windows the size matching the display scale.
const ARTWORK: &[(u32, &[u8], &[u8])] = &[
    (
        16,
        include_bytes!("../../icon/tray/tray-16.png"),
        include_bytes!("../../icon/tray/globe-16.png"),
    ),
    (
        18,
        include_bytes!("../../icon/tray/tray-18.png"),
        include_bytes!("../../icon/tray/globe-18.png"),
    ),
    (
        20,
        include_bytes!("../../icon/tray/tray-20.png"),
        include_bytes!("../../icon/tray/globe-20.png"),
    ),
    (
        22,
        include_bytes!("../../icon/tray/tray-22.png"),
        include_bytes!("../../icon/tray/globe-22.png"),
    ),
    (
        24,
        include_bytes!("../../icon/tray/tray-24.png"),
        include_bytes!("../../icon/tray/globe-24.png"),
    ),
    (
        32,
        include_bytes!("../../icon/tray/tray-32.png"),
        include_bytes!("../../icon/tray/globe-32.png"),
    ),
    (
        36,
        include_bytes!("../../icon/tray/tray-36.png"),
        include_bytes!("../../icon/tray/globe-36.png"),
    ),
    (
        40,
        include_bytes!("../../icon/tray/tray-40.png"),
        include_bytes!("../../icon/tray/globe-40.png"),
    ),
    (
        44,
        include_bytes!("../../icon/tray/tray-44.png"),
        include_bytes!("../../icon/tray/globe-44.png"),
    ),
    (
        48,
        include_bytes!("../../icon/tray/tray-48.png"),
        include_bytes!("../../icon/tray/globe-48.png"),
    ),
    (
        64,
        include_bytes!("../../icon/tray/tray-64.png"),
        include_bytes!("../../icon/tray/globe-64.png"),
    ),
];

/// One decoded artwork size: `size` x `size` RGBA frame pixels and the globe mask
/// (one coverage byte per pixel).
#[derive(Clone)]
struct Artwork {
    size: u32,
    rgba: Vec<u8>,
    globe: Vec<u8>,
}

fn artwork() -> Result<Vec<Artwork>> {
    ARTWORK
        .iter()
        .map(|&(size, frame, globe)| {
            let frame = image::load_from_memory_with_format(frame, image::ImageFormat::Png)
                .with_context(|| format!("Cannot decode embedded {size}px tray icon"))?
                .to_rgba8();
            let globe = image::load_from_memory_with_format(globe, image::ImageFormat::Png)
                .with_context(|| format!("Cannot decode embedded {size}px globe mask"))?
                .to_luma8();
            if frame.dimensions() != (size, size) || globe.dimensions() != (size, size) {
                bail!(
                    "Embedded {size}px tray icon has size {:?} / {:?}",
                    frame.dimensions(),
                    globe.dimensions()
                );
            }
            Ok(Artwork {
                size,
                rgba: frame.into_raw(),
                globe: globe.into_raw(),
            })
        })
        .collect()
}

/// The Windows notification area shows small icons (16 px at 100 % scaling,
/// 20 px at 125 %, ...): the smallest pre-rendered size covering 16 px at `scale`.
#[cfg(any(windows, test))]
fn windows_icon_size(scale: f64) -> u32 {
    const SIZES: [u32; 6] = [16, 20, 24, 32, 40, 48];
    let wanted = (16.0 * scale.clamp(1.0, 3.0)).round() as u32;
    SIZES
        .into_iter()
        .find(|&size| size >= wanted)
        .unwrap_or(SIZES[SIZES.len() - 1])
}

/// Status color of the globe: green when everything works, red when blocked,
/// gray while starting or when the app itself failed.
fn status_rgb(color: Color) -> [u8; 3] {
    match color {
        Color::Waiting | Color::Error => [170, 180, 190],
        Color::Blocked => [255, 80, 80],
        Color::Allowed => [60, 220, 110],
        Color::Partial => [255, 185, 40],
    }
}

/// The frame with the globe painted in the status color through its mask.
fn pixels(art: &Artwork, color: Color) -> Vec<u8> {
    let rgb = status_rgb(color);
    let mut rgba = art.rgba.clone();
    for (pixel, &coverage) in rgba.as_chunks_mut::<4>().0.iter_mut().zip(&art.globe) {
        if coverage == 0 {
            continue;
        }
        let alpha = coverage as f32 / 255.0;
        let dst_alpha = pixel[3] as f32 / 255.0;
        let out_alpha = alpha + dst_alpha * (1.0 - alpha);
        for channel in 0..3 {
            let under = pixel[channel] as f32;
            let value =
                (rgb[channel] as f32 * alpha + under * dst_alpha * (1.0 - alpha)) / out_alpha;
            pixel[channel] = value.round() as u8;
        }
        pixel[3] = (out_alpha * 255.0).round() as u8;
    }
    rgba
}

#[cfg(windows)]
pub fn run(options: Options) -> Result<()> {
    let directory = crate::windows::user_data_directory()?;
    // Release builds have no console window: keep diagnostics in a log file.
    if !crate::windows::has_stderr() {
        crate::windows::redirect_stderr(&directory.join("agoc-tray.log"))?;
    }
    if options.installed_helper {
        bail!("--installed-helper is not available on Windows; the tray asks for UAC consent");
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("agoc-tray.lock"))
        .context("Cannot open tray instance lock")?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            eprintln!("AGOC tray is already running; ignoring duplicate launch");
            return Ok(());
        }
        Err(std::fs::TryLockError::Error(error)) => {
            return Err(error).context("Cannot acquire tray instance lock")
        }
    }
    desktop::run(options)
}

#[cfg(unix)]
pub fn run(options: Options) -> Result<()> {
    let uid = Command::new("/usr/bin/id").arg("-u").output()?;
    if !uid.status.success() || uid.stdout == b"0\n" {
        bail!("Run agoc-tray as your desktop user, NOT with sudo");
    }
    let uid: u32 = std::str::from_utf8(&uid.stdout)
        .context("Invalid output from id -u")?
        .trim()
        .parse()
        .context("Invalid desktop user ID")?;
    let Some(_instance_lock) = InstanceLock::acquire(uid)? else {
        eprintln!("AGOC tray is already running; ignoring duplicate launch");
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    return linux::run(options);
    #[cfg(target_os = "macos")]
    return desktop::run(options);
}

#[cfg(unix)]
struct InstanceLock {
    _file: File,
}

#[cfg(unix)]
impl InstanceLock {
    fn acquire(uid: u32) -> Result<Option<Self>> {
        let path = std::env::temp_dir().join(format!("agoc-tray-{uid}.lock"));
        Self::acquire_at(&path, uid)
    }

    fn acquire_at(path: &Path, uid: u32) -> Result<Option<Self>> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("Cannot open tray instance lock {}", path.display()))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            bail!("Tray instance lock has unsafe ownership or permissions");
        }
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            Ok(Some(Self { _file: file }))
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(error).context("Cannot acquire tray instance lock")
            }
        }
    }
}

struct Worker {
    commands: Sender<()>,
}

impl Worker {
    fn start(options: Options, notify: impl Fn(Event) + Send + 'static) -> Result<Self> {
        let (commands, receiver) = mpsc::channel();
        thread::Builder::new()
            .name("agoc-monitor".into())
            .spawn(move || {
                if let Err(error) = work(options, receiver, &notify) {
                    notify(Event::Failed(format!("{error:#}")));
                }
            })?;
        Ok(Self { commands })
    }

    fn quit(&self) -> Result<()> {
        self.commands
            .send(())
            .context("Monitor worker already stopped")
    }
}

/// Monitor command line; `control` holds the control-endpoint arguments.
fn monitor_arguments(options: &Options, control: &[String]) -> Vec<String> {
    if options.installed_helper {
        return std::iter::once("desktop-helper".to_string())
            .chain(control.iter().cloned())
            .collect();
    }
    let mut arguments = vec![
        "run".into(),
        "--interval".into(),
        options.interval.to_string(),
    ];
    arguments.extend(control.iter().cloned());
    if let Some(state) = &options.network.state {
        arguments.extend(["--state".into(), state.to_string_lossy().into_owned()]);
    }
    if let Some(interface) = &options.network.direct_interface {
        arguments.extend(["--direct-interface".into(), interface.clone()]);
    }
    for domain in &options.domain {
        arguments.extend(["--domain".into(), domain.clone()]);
    }
    arguments
}

#[cfg(any(target_os = "macos", test))]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Quotes one argument for the Windows command line (`CommandLineToArgvW`
/// rules), so a path or domain can never split into extra arguments.
#[cfg(any(windows, test))]
fn windows_quote(argument: &str) -> String {
    if !argument.is_empty() && !argument.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return argument.into();
    }
    let mut quoted = String::from('"');
    let mut backslashes = 0;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
        } else {
            if character == '"' {
                // Escape the preceding backslashes and the quote itself.
                quoted.extend(std::iter::repeat_n('\\', backslashes + 1));
            }
            backslashes = 0;
        }
        quoted.push(character);
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes));
    quoted.push('"');
    quoted
}

/// Removes the `\\?\` prefix that `canonicalize` adds on Windows; the shell
/// does not accept it in `ShellExecuteEx`.
#[cfg(windows)]
fn plain_path(path: std::path::PathBuf) -> std::path::PathBuf {
    match path.to_str().and_then(|text| text.strip_prefix(r"\\?\")) {
        Some(rest) if !rest.starts_with("UNC\\") => rest.into(),
        _ => path,
    }
}

#[cfg(unix)]
fn elevation(program: &Path, arguments: &[String], installed: bool) -> Result<Command> {
    if installed {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("-n").arg("--").arg(program).args(arguments);
        return Ok(command);
    }
    #[cfg(target_os = "linux")]
    {
        if !Path::new("/usr/bin/pkexec").is_file() {
            bail!("pkexec is required. Install polkit and run a desktop authentication agent");
        }
        let mut command = Command::new("/usr/bin/pkexec");
        command
            .arg("--disable-internal-agent")
            .arg(program)
            .args(arguments);
        Ok(command)
    }
    #[cfg(target_os = "macos")]
    {
        let shell_command = std::iter::once(program.to_string_lossy().into_owned())
            .chain(arguments.iter().cloned())
            .map(|value| shell_quote(&value))
            .collect::<Vec<_>>()
            .join(" ");
        let mut command = Command::new("/usr/bin/osascript");
        command.args([
            "-e",
            "on run argv\n do shell script (item 1 of argv) with administrator privileges\nend run",
            &shell_command,
        ]);
        Ok(command)
    }
}

/// The privileged monitor process, started through the platform's
/// administrator authorization.
struct Helper {
    #[cfg(unix)]
    child: std::process::Child,
    #[cfg(windows)]
    process: crate::windows::ElevatedProcess,
}

impl Helper {
    #[cfg(unix)]
    fn start(program: &Path, arguments: &[String], installed: bool) -> Result<Self> {
        let child = elevation(program, arguments, installed)?
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .context("Cannot start administrator authorization")?;
        Ok(Self { child })
    }

    /// Shows the UAC prompt and blocks until it is answered. The helper's
    /// console is hidden; it logs to `%ProgramData%\agoc\agoc.log`.
    #[cfg(windows)]
    fn start(program: &Path, arguments: &[String], _installed: bool) -> Result<Self> {
        let parameters = arguments
            .iter()
            .map(|argument| windows_quote(argument))
            .collect::<Vec<_>>()
            .join(" ");
        Ok(Self {
            process: crate::windows::ElevatedProcess::start(program, &parameters)?,
        })
    }

    /// `Some((success, description))` once the helper has exited.
    fn try_wait(&mut self) -> Result<Option<(bool, String)>> {
        #[cfg(unix)]
        return Ok(self
            .child
            .try_wait()?
            .map(|status| (status.success(), status.to_string())));
        #[cfg(windows)]
        return Ok(self
            .process
            .try_wait()?
            .map(|code| (code == 0, format!("exit code {code}"))));
    }

    fn cancel(&mut self) -> Result<()> {
        #[cfg(unix)]
        {
            self.child
                .kill()
                .context("Cannot cancel administrator authorization")?;
            self.child.wait()?;
        }
        #[cfg(windows)]
        self.process.terminate();
        Ok(())
    }
}

/// Where the monitor connects back to the tray: a Unix socket in a private
/// 0700 directory, or on Windows a loopback port plus a random token that the
/// helper must present before anything else is exchanged.
struct ControlListener {
    #[cfg(unix)]
    _directory: tempfile::TempDir,
    #[cfg(unix)]
    path: std::path::PathBuf,
    #[cfg(unix)]
    listener: UnixListener,
    #[cfg(windows)]
    listener: std::net::TcpListener,
    #[cfg(windows)]
    token: String,
}

impl ControlListener {
    #[cfg(unix)]
    fn bind() -> Result<Self> {
        let temporary_root = std::env::temp_dir()
            .canonicalize()
            .context("Cannot resolve temporary directory")?;
        let directory = tempfile::Builder::new()
            .prefix("agoc-tray-")
            .tempdir_in(temporary_root)?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("control.sock");
        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            _directory: directory,
            path,
            listener,
        })
    }

    #[cfg(windows)]
    fn bind() -> Result<Self> {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            token: crate::windows::random_token()?,
        })
    }

    fn arguments(&self) -> Result<Vec<String>> {
        #[cfg(unix)]
        return Ok(vec![
            "--control".into(),
            self.path.to_string_lossy().into_owned(),
        ]);
        #[cfg(windows)]
        return Ok(vec![
            "--control".into(),
            self.listener.local_addr()?.to_string(),
            "--control-token".into(),
            self.token.clone(),
        ]);
    }

    /// The authenticated monitor connection, if one is waiting.
    fn accept(&self) -> Result<Option<control::Stream>> {
        let stream = match self.listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        // On macOS/BSD and Windows, accepted sockets inherit non-blocking mode.
        stream.set_nonblocking(false)?;
        #[cfg(windows)]
        {
            use std::io::Read;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            // Read byte by byte: nothing after the token line may be buffered away.
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while line.len() <= control::TOKEN_LENGTH {
                match (&stream).read(&mut byte) {
                    Ok(1) if byte[0] == b'\n' => break,
                    Ok(1) => line.push(byte[0]),
                    _ => {
                        line.clear();
                        break;
                    }
                }
            }
            let received = String::from_utf8_lossy(&line);
            if !control::token_matches(&self.token, &received) {
                eprintln!("Rejected a control connection without the expected token");
                return Ok(None);
            }
            stream.set_read_timeout(None)?;
        }
        Ok(Some(stream))
    }
}

fn helper_program() -> Result<std::path::PathBuf> {
    let program = std::env::current_exe()?
        .parent()
        .context("Cannot locate executable directory")?
        .join(format!("agoc{}", std::env::consts::EXE_SUFFIX))
        .canonicalize()
        .context("Keep agoc and agoc-tray in the same directory")?;
    #[cfg(windows)]
    let program = plain_path(program);
    Ok(program)
}

fn work(options: Options, commands: Receiver<()>, notify: &impl Fn(Event)) -> Result<()> {
    let program = helper_program()?;
    let mut options = options;
    if let Some(state) = &options.network.state {
        let state = state
            .canonicalize()
            .context("Saved-baseline mode requires an existing baseline file")?;
        #[cfg(windows)]
        let state = plain_path(state);
        options.network.state = Some(state);
    }
    let listener = ControlListener::bind()?;
    let mut child = Helper::start(
        &program,
        &monitor_arguments(&options, &listener.arguments()?),
        options.installed_helper,
    )?;
    let started = Instant::now();
    let mut stream = loop {
        if let Some(stream) = listener.accept()? {
            break stream;
        }
        if let Some((_, status)) = child.try_wait()? {
            bail!("Administrator helper exited before connecting: {status}. Check authorization and its log output");
        }
        if commands.try_recv() != Err(TryRecvError::Empty) {
            child.cancel()?;
            notify(Event::Finished);
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(120) {
            child.cancel()?;
            bail!("Administrator authorization timed out");
        }
        thread::sleep(Duration::from_millis(100));
    };
    drop(listener);
    let reader = stream.try_clone()?;
    let (messages, incoming) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            let message = line
                .map_err(anyhow::Error::from)
                .and_then(|line| Ok(serde_json::from_str::<Message>(&line)?));
            if messages.send(message).is_err() {
                return;
            }
        }
    });
    let mut quit_sent = false;
    let mut stopped = false;
    loop {
        if !quit_sent && commands.try_recv() != Err(TryRecvError::Empty) {
            control::send(&mut stream, &Message::Quit)?;
            quit_sent = true;
        }
        for message in incoming.try_iter() {
            match message? {
                Message::Stopped => stopped = true,
                message => notify(Event::Status(message)),
            }
        }
        if let Some((success, status)) = child.try_wait()? {
            // Drain the reader after process exit before checking the final acknowledgement.
            for message in incoming.iter() {
                match message? {
                    Message::Stopped => stopped = true,
                    message => notify(Event::Status(message)),
                }
            }
            if stopped && success {
                notify(Event::Finished);
                return Ok(());
            }
            bail!("Monitor exited without confirmed firewall cleanup ({status}); protection may remain blocked");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn only_one_tray_instance_can_hold_the_lock() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let uid = directory.path().metadata().unwrap().uid();
        let path = directory.path().join("agoc-tray.lock");
        let first = InstanceLock::acquire_at(&path, uid).unwrap().unwrap();
        assert!(InstanceLock::acquire_at(&path, uid).unwrap().is_none());
        drop(first);
        assert!(InstanceLock::acquire_at(&path, uid).unwrap().is_some());
    }

    #[test]
    fn shell_arguments_cannot_become_commands() {
        assert_eq!(shell_quote("a'b; $HOME"), "'a'\\''b; $HOME'");
    }

    #[test]
    fn windows_arguments_cannot_split_or_escape_quotes() {
        assert_eq!(windows_quote("run"), "run");
        assert_eq!(windows_quote(""), "\"\"");
        assert_eq!(windows_quote("Wi-Fi 2"), "\"Wi-Fi 2\"");
        assert_eq!(
            windows_quote(r"C:\Program Files\AGOC\"),
            r#""C:\Program Files\AGOC\\""#
        );
        assert_eq!(windows_quote(r#"a"b"#), r#""a\"b""#);
        assert_eq!(windows_quote(r#"a\"b c"#), r#""a\\\"b c""#);
        assert_eq!(windows_quote(r"C:\dir\file.txt"), r"C:\dir\file.txt");
    }

    #[test]
    fn indicators_reflect_both_address_families() {
        let (sender, _receiver) = mpsc::channel();
        let worker = Worker { commands: sender };
        let mut view = View::default();
        for (v4, v6, color) in [
            (false, false, Color::Blocked),
            (true, false, Color::Partial),
            (false, true, Color::Partial),
            (true, true, Color::Allowed),
        ] {
            assert!(!view
                .event(
                    Event::Status(Message::Status {
                        allow4: v4,
                        allow6: v6,
                        addresses: 2,
                        network: crate::network::NetworkStatus {
                            ipv4: crate::network::FamilyStatus {
                                original: Some("8.8.8.8".parse().unwrap()),
                                current: Some(
                                    if v4 { "1.1.1.1" } else { "8.8.8.8" }.parse().unwrap()
                                ),
                                error: None,
                            },
                            ipv6: crate::network::FamilyStatus {
                                original: Some("2001:4860:4860::8888".parse().unwrap()),
                                current: Some(
                                    if v6 {
                                        "2606:4700:4700::1111"
                                    } else {
                                        "2001:4860:4860::8888"
                                    }
                                    .parse()
                                    .unwrap()
                                ),
                                error: None,
                            },
                            ..Default::default()
                        }
                    }),
                    &worker
                )
                .unwrap());
            assert_eq!(view.color, color);
            assert_eq!(view.label.contains("AI OPEN"), v4 || v6);
            assert!(view.details[0].starts_with("IPv4 "));
            assert!(view.details[0].contains("8.8.8.8"));
            assert!(view.details[1].contains(if v6 {
                "2001:4860:4860::8888 → 2606:4700:4700::1111"
            } else {
                "unchanged 2001:4860:4860::8888"
            }));
        }
        assert!(!view.event(Event::Quit, &worker).unwrap());
        assert!(view.quitting);
        assert!(view.event(Event::Finished, &worker).unwrap());
        for art in artwork().unwrap() {
            assert_eq!(
                pixels(&art, Color::Blocked).len(),
                (art.size * art.size * 4) as usize
            );
        }
    }

    #[test]
    fn windows_icon_matches_display_scaling() {
        for (scale, size) in [
            (1.0, 16),
            (1.25, 20),
            (1.5, 24),
            (1.75, 32),
            (2.0, 32),
            (2.5, 40),
            (3.0, 48),
            (4.0, 48),
            (0.5, 16),
        ] {
            assert_eq!(windows_icon_size(scale), size, "{scale}");
        }
        let available: Vec<_> = artwork().unwrap().iter().map(|art| art.size).collect();
        for size in [16, 20, 24, 32, 40, 48] {
            assert!(available.contains(&size));
        }
    }

    #[test]
    fn embedded_artwork_is_visible_and_only_the_globe_is_recolored() {
        let all = artwork().unwrap();
        assert_eq!(
            all.iter().map(|art| art.size).collect::<Vec<_>>(),
            [16, 18, 20, 22, 24, 32, 36, 40, 44, 48, 64]
        );
        for art in &all {
            let size = art.size;
            assert_eq!(art.rgba.len(), (size * size * 4) as usize);
            assert_eq!(art.globe.len(), (size * size) as usize);
            let frame = art.rgba.as_chunks::<4>().0;
            // Opaque blue rim exists at every size.
            assert!(frame
                .iter()
                .any(|pixel| pixel[3] == 255 && pixel[2] > 200 && pixel[0] < 100));
            // Fully covered globe pixels exist and lie on the opaque body.
            let solid: Vec<_> = (0..frame.len()).filter(|&i| art.globe[i] == 255).collect();
            assert!(!solid.is_empty(), "{size}px");
            assert!(solid.iter().all(|&i| frame[i][3] == 255), "{size}px");
            for color in [
                Color::Waiting,
                Color::Error,
                Color::Blocked,
                Color::Allowed,
                Color::Partial,
            ] {
                let rgb = status_rgb(color);
                let rendered = pixels(art, color);
                let rendered = rendered.as_chunks::<4>().0;
                for i in 0..frame.len() {
                    match art.globe[i] {
                        0 => assert_eq!(rendered[i], frame[i], "{size}px"),
                        255 => assert_eq!(rendered[i], [rgb[0], rgb[1], rgb[2], 255], "{size}px"),
                        _ => {}
                    }
                }
            }
        }
    }

    #[test]
    fn menu_rows_stay_narrow_with_long_errors_and_ipv6() {
        let (commands, _receiver) = mpsc::channel();
        let worker = Worker { commands };
        let long_error = "Current IP unknown: IP probe failed (https://api6.ipify.org, \
            interface None): error sending request for url (https://api6.ipify.org/): \
            client error (Connect): tcp connect error: Network is unreachable (os error 101); \
            Original IP unknown: IP probe failed (https://api6.ipify.org, interface \
            Some(\"enp2s0\")): operation timed out";
        let mut view = View::default();
        view.event(
            Event::Status(Message::Status {
                allow4: true,
                allow6: false,
                addresses: 123_456,
                network: crate::network::NetworkStatus {
                    interface: Some("enp2s0".into()),
                    ipv4: crate::network::FamilyStatus {
                        original: Some("203.0.113.10".parse().unwrap()),
                        current: Some("198.51.100.200".parse().unwrap()),
                        error: None,
                    },
                    ipv6: crate::network::FamilyStatus {
                        original: Some("2a01:4f8:c0c:1234:5678:9abc:def0:1234".parse().unwrap()),
                        current: None,
                        error: Some(long_error.into()),
                    },
                    error: None,
                },
            }),
            &worker,
        )
        .unwrap();
        assert_eq!(view.label, "AI OPEN (IPv4, 123456 IPs)");
        assert_eq!(
            view.details[0],
            "IPv4 ALLOWED: 203.0.113.10 → 198.51.100.200"
        );
        assert_eq!(
            view.details[1],
            "IPv6 BLOCKED: unavailable (Network is unreachable)"
        );
        assert_eq!(view.details[2], "Direct interface: enp2s0");
        assert_eq!(
            family_row(
                &crate::network::FamilyStatus {
                    original: Some("2a01:4f8:c0c:1234:5678:9abc:def0:1234".parse().unwrap()),
                    current: Some("2a02:4780:10:5be4:aaaa:bbbb:cccc:7".parse().unwrap()),
                    error: None,
                },
                "IPv6",
                true,
            ),
            "IPv6 ALLOWED: 2a01:4f8:c0c:…:1234 → 2a02:4780:10:…:7"
        );
        view.event(Event::Failed(long_error.repeat(5)), &worker)
            .unwrap();
        assert_eq!(view.label, "Error: Network is unreachable");
        assert_eq!(view.color, Color::Error);
        for row in std::iter::once(&view.label).chain(&view.details) {
            assert!(row.chars().count() <= MENU_WIDTH, "{row}");
        }
        assert_eq!(fit(&"x".repeat(200)).chars().count(), MENU_WIDTH);
    }

    #[test]
    fn changed_ipv4_is_green_when_ipv6_is_not_in_use() {
        let (commands, _receiver) = mpsc::channel();
        let worker = Worker { commands };
        let ipv4 = crate::network::FamilyStatus {
            original: Some("8.8.8.8".parse().unwrap()),
            current: Some("1.1.1.1".parse().unwrap()),
            error: None,
        };
        let status = |allow4, ipv6| {
            Event::Status(Message::Status {
                allow4,
                allow6: false,
                addresses: 2,
                network: crate::network::NetworkStatus {
                    ipv4: ipv4.clone(),
                    ipv6,
                    ..Default::default()
                },
            })
        };
        let no_ipv6 = crate::network::FamilyStatus {
            original: Some("2001:4860:4860::8888".parse().unwrap()),
            current: None,
            error: Some("Current IP unknown: no route".into()),
        };

        // IPv4 changed, no IPv6 on the current route -> green.
        let mut view = View::default();
        view.event(status(true, no_ipv6.clone()), &worker).unwrap();
        assert_eq!(view.color, Color::Allowed);
        assert!(view.label.contains("AI OPEN"));
        assert!(view.details[1].contains("BLOCKED"));

        // IPv6 reachable but unchanged -> still amber.
        let mut view = View::default();
        let unchanged = crate::network::FamilyStatus {
            original: Some("2001:4860:4860::8888".parse().unwrap()),
            current: Some("2001:4860:4860::8888".parse().unwrap()),
            error: None,
        };
        view.event(status(true, unchanged), &worker).unwrap();
        assert_eq!(view.color, Color::Partial);

        // IPv4 not allowed -> red, even without IPv6.
        let mut view = View::default();
        view.event(status(false, no_ipv6), &worker).unwrap();
        assert_eq!(view.color, Color::Blocked);
    }

    #[test]
    fn unknown_original_cannot_show_ok_even_if_permissions_are_reported() {
        let (commands, _receiver) = mpsc::channel();
        let worker = Worker { commands };
        let mut view = View::default();
        view.event(
            Event::Status(Message::Status {
                allow4: true,
                allow6: false,
                addresses: 4,
                network: Default::default(),
            }),
            &worker,
        )
        .unwrap();
        assert_eq!(view.color, Color::Blocked);
        assert_eq!(view.label, "Original IP unknown - AI CLOSE");
        assert!(!view.label.contains("AI OPEN"));
    }

    #[test]
    fn automatic_launch_needs_no_saved_baseline() {
        let control = ["--control".to_string(), "/tmp/control.sock".to_string()];
        let options = Options::try_parse_from(["agoc-tray"]).unwrap();
        let arguments = monitor_arguments(&options, &control);
        assert!(!arguments.iter().any(|arg| arg == "--state"));
        assert!(arguments.ends_with(&control));
        let options = Options::try_parse_from(["agoc-tray", "--direct-interface", "en0"]).unwrap();
        assert!(monitor_arguments(&options, &control)
            .windows(2)
            .any(|args| args == ["--direct-interface", "en0"]));
        assert!(Options::try_parse_from([
            "agoc-tray",
            "--direct-interface",
            "en0",
            "--state",
            "/tmp/baseline"
        ])
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn installed_mode_uses_only_the_restricted_helper() {
        let control = ["--control".to_string(), "/tmp/control.sock".to_string()];
        let options = Options::try_parse_from(["agoc-tray", "--installed-helper"]).unwrap();
        assert_eq!(
            monitor_arguments(&options, &control),
            ["desktop-helper", "--control", "/tmp/control.sock"]
        );
        for flag in ["--state", "--direct-interface", "--interval", "--domain"] {
            assert!(
                Options::try_parse_from(["agoc-tray", "--installed-helper", flag, "x"]).is_err()
            );
        }
        let command = elevation(
            Path::new("/opt/agoc/agoc"),
            &monitor_arguments(&options, &control),
            true,
        )
        .unwrap();
        assert_eq!(command.get_program(), "/usr/bin/sudo");
        assert_eq!(command.get_args().take(2).collect::<Vec<_>>(), ["-n", "--"]);
    }

    #[cfg(unix)]
    #[test]
    fn accepted_control_stream_blocks_instead_of_returning_would_block() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();

        let mut client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let (stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(false).unwrap();

        let (tx, rx) = mpsc::channel();
        let reader = stream.try_clone().unwrap();
        thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(reader).read_line(&mut line);
            let _ = tx.send(result.map(|_| line));
        });

        thread::sleep(Duration::from_millis(30));
        assert!(
            matches!(rx.try_recv(), Err(TryRecvError::Empty)),
            "Reader must block instead of failing with WouldBlock/EAGAIN"
        );
        control::send(&mut client, &Message::Stopped).unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().is_ok());
    }
}
