mod firewall;

use agoc::control::{Control, Message};
use agoc::{
    executable,
    network::{self, FamilyStatus, NetworkOptions, NetworkStatus},
};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

/// Hostnames whose addresses are blocked until the public IP changes.
///
/// Only hostnames served from addresses dedicated to the service are listed.
/// Hostnames on shared front ends are deliberately left out, because blocking
/// their IPs would also break unrelated sites: Gemini (Google front ends shared
/// with Search, Gmail, YouTube), Bing-hosted Copilot endpoints
/// (`copilot.live.com`, `sydney.bing.com`), Microsoft 365 front doors
/// (`copilot.cloud.microsoft`, `substrate.office.com`), Auth0/Vercel/Azure Front
/// Door hosted pages (`auth0.openai.com`, `status.openai.com`, `cdn.openai.com`).
/// Those are NOT blocked.
///
/// DNS failures for these hostnames fail closed (block until resolved), as do
/// hostnames added with `--domain`.
const DEFAULT_DOMAINS: &[&str] = &[
    // Anthropic / Claude
    "anthropic.com",
    "www.anthropic.com",
    "api.anthropic.com",
    "console.anthropic.com",
    "platform.claude.com",
    "claude.ai",
    "www.claude.ai",
    "claude.com",
    "www.claude.com",
    "claudeusercontent.com",
    "downloads.claude.ai",
];

/// Other AI services, blocked the same way. Their DNS failures are only logged:
/// a renamed or retired endpoint must not keep Claude blocked forever.
const OTHER_AI_DOMAINS: &[&str] = &[
    // OpenAI / ChatGPT / Sora / Codex
    "openai.com",
    "www.openai.com",
    "api.openai.com",
    "platform.openai.com",
    "auth.openai.com",
    "help.openai.com",
    "chat.openai.com",
    "chatgpt.com",
    "www.chatgpt.com",
    "ab.chatgpt.com",
    "sora.chatgpt.com",
    "operator.chatgpt.com",
    "oaistatic.com",
    "cdn.oaistatic.com",
    "files.oaiusercontent.com",
    "sora.com",
    "www.sora.com",
    // GitHub Copilot (IDE, CLI, coding agent)
    "githubcopilot.com",
    "api.githubcopilot.com",
    "api.individual.githubcopilot.com",
    "api.business.githubcopilot.com",
    "api.enterprise.githubcopilot.com",
    "proxy.individual.githubcopilot.com",
    "proxy.business.githubcopilot.com",
    "proxy.enterprise.githubcopilot.com",
    "telemetry.individual.githubcopilot.com",
    "telemetry.business.githubcopilot.com",
    "telemetry.enterprise.githubcopilot.com",
    "copilot-proxy.githubusercontent.com",
    "copilot-telemetry.githubusercontent.com",
    "origin-tracker.githubusercontent.com",
    "copilot-workspace.githubnext.com",
    // Microsoft Copilot
    "copilot.microsoft.com",
    "m365copilot.com",
    "www.m365copilot.com",
];
const LEASE_SECONDS: u64 = 30;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Record the original public address. Run WITHOUT address substitution.
    Baseline {
        #[arg(long, default_value = "agoc-baseline.txt")]
        state: PathBuf,
        /// Also record IPv6. Otherwise protected IPv6 is ALWAYS blocked.
        #[arg(long)]
        ipv6: bool,
    },
    /// Monitor public addresses and manage the system firewall (root).
    Run {
        #[command(flatten)]
        network: NetworkOptions,
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=10))]
        interval: u64,
        /// Additional exact hostname; repeat for multiple hosts.
        #[arg(long, value_parser = domain)]
        domain: Vec<String>,
        #[arg(long, hide = true)]
        control: Option<PathBuf>,
    },
    /// Explicitly remove protection (root). Stop the monitor first.
    Uninstall {
        /// Succeed when AGOC's rules are already absent.
        #[arg(long)]
        if_present: bool,
    },
    #[command(hide = true)]
    Guard,
    /// Restricted entry point for the installed desktop autostart.
    #[command(hide = true)]
    DesktopHelper {
        #[arg(long)]
        control: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Baseline {
    v4: Ipv4Addr,
    v6: Option<Ipv6Addr>,
}

/// Baseline file header. It keeps the pre-rename `antiban` name on purpose, so
/// baseline files saved before the project was renamed to AGOC stay readable.
const BASELINE_HEADER: &str = "antiban-v1";

impl Baseline {
    fn parse(text: &str) -> Result<Self> {
        let mut lines = text.lines();
        if lines.next() != Some(BASELINE_HEADER) {
            bail!("Invalid baseline version");
        }
        let v4 = lines.next().context("Missing IPv4 baseline")?.parse()?;
        let v6 = match lines.next().context("Missing IPv6 baseline")? {
            "-" => None,
            value => Some(value.parse()?),
        };
        if lines.next().is_some() {
            bail!("Unexpected baseline data");
        }
        Ok(Self { v4, v6 })
    }

    fn encode(&self) -> String {
        format!(
            "{BASELINE_HEADER}\n{}\n{}\n",
            self.v4,
            self.v6.map_or_else(|| "-".into(), |ip| ip.to_string())
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Policy {
    pub addresses: BTreeSet<IpAddr>,
    pub allow4: bool,
    pub allow6: bool,
}

impl Policy {
    fn block(&mut self) {
        self.allow4 = false;
        self.allow6 = false;
    }

    fn encode(&self) -> String {
        format!(
            "{} {} {}\n",
            u8::from(self.allow4),
            u8::from(self.allow6),
            self.addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    fn parse(line: &str) -> Result<Self> {
        let fields: Vec<_> = line.trim_end_matches('\n').split(' ').collect();
        if fields.len() != 3 {
            bail!("Invalid guardian message");
        }
        let flag = |s| match s {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => anyhow::bail!("Invalid policy flag"),
        };
        let addresses = if fields[2].is_empty() {
            BTreeSet::new()
        } else {
            fields[2]
                .split(',')
                .map(str::parse)
                .collect::<std::result::Result<_, _>>()?
        };
        Ok(Self {
            addresses,
            allow4: flag(fields[0])?,
            allow6: flag(fields[1])?,
        })
    }
}

fn domain(value: &str) -> std::result::Result<String, String> {
    let valid = value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if valid {
        Ok(value.to_ascii_lowercase())
    } else {
        Err("Expected an exact ASCII DNS hostname, not a URL or wildcard".into())
    }
}

fn require_root() -> Result<()> {
    let output = Command::new("/usr/bin/id").arg("-u").output()?;
    if !output.status.success() || output.stdout != b"0\n" {
        bail!("This operation requires root; run with sudo");
    }
    Ok(())
}

fn resolve_domains(
    strict: &BTreeSet<String>,
    best_effort: &BTreeSet<String>,
) -> Result<(BTreeSet<IpAddr>, bool)> {
    let mut addresses = BTreeSet::new();
    let mut dns_ok = true;
    thread::scope(|scope| {
        let lookups = strict
            .iter()
            .map(|host| (host, true))
            .chain(best_effort.iter().map(|host| (host, false)))
            .map(|(host, required)| {
                scope.spawn(move || (host, required, (host.as_str(), 443).to_socket_addrs()))
            })
            .collect::<Vec<_>>();
        for lookup in lookups {
            let (host, required, result) = lookup
                .join()
                .map_err(|_| anyhow::anyhow!("DNS lookup thread panicked"))?;
            let resolved: Vec<_> = match result {
                Ok(resolved) => resolved.map(|address| address.ip()).collect(),
                Err(error) => {
                    eprintln!("DNS failed for {host}: {error}");
                    Vec::new()
                }
            };
            if resolved.is_empty() && required {
                eprintln!("No addresses for required host {host}; blocking");
                dns_ok = false;
            }
            addresses.extend(resolved);
        }
        Ok::<(), anyhow::Error>(())
    })?;
    Ok((addresses, dns_ok))
}

fn record_baseline(path: &Path, ipv6: bool) -> Result<()> {
    let v4 = match network::public_ip(false, None)? {
        IpAddr::V4(ip) => ip,
        _ => unreachable!(),
    };
    let v6 = if ipv6 {
        match network::public_ip(true, None)? {
            IpAddr::V6(ip) => Some(ip),
            _ => unreachable!(),
        }
    } else {
        None
    };
    let baseline = Baseline { v4, v6 };
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .context("Cannot create baseline (existing files are never overwritten)")?;
    file.write_all(baseline.encode().as_bytes())?;
    file.sync_all()?;
    println!(
        "Baseline saved to {}: IPv4 {v4}, IPv6 {v6:?}",
        path.display()
    );
    if !ipv6 {
        println!("Protected IPv6 will remain BLOCKED, even when IPv4 changes.");
    }
    Ok(())
}

fn read_baseline(path: &Path) -> Result<Baseline> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!("Baseline must be a root-owned regular file, not writable by group/others");
        }
    }
    Baseline::parse(&fs::read_to_string(path)?)
}

struct Guardian {
    child: std::process::Child,
    input: Option<std::process::ChildStdin>,
    output: BufReader<std::process::ChildStdout>,
    last: Policy,
    dead: bool,
}

impl Guardian {
    fn start() -> Result<Self> {
        let mut child = Command::new(std::env::current_exe()?)
            .arg("guard")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        Ok(Self {
            input: child.stdin.take(),
            output: BufReader::new(child.stdout.take().context("No guardian stdout")?),
            child,
            last: Policy::default(),
            dead: false,
        })
    }

    fn apply(&mut self, policy: &Policy) -> Result<()> {
        self.last = policy.clone();
        let input = self.input.as_mut().context("Guardian input closed")?;
        if let Err(error) = input
            .write_all(policy.encode().as_bytes())
            .and_then(|()| input.flush())
        {
            self.dead = true;
            let mut reply = String::new();
            if self.output.read_line(&mut reply).is_ok() {
                if let Some(message) = reply.strip_prefix("ERR ") {
                    bail!("{}", message.trim_end());
                }
            }
            return Err(error.into());
        }
        let mut reply = String::new();
        self.output.read_line(&mut reply)?;
        if reply == "OK\n" {
            return Ok(());
        }
        self.dead = true;
        if let Some(message) = reply.strip_prefix("ERR ") {
            bail!("{}", message.trim_end());
        }
        bail!("Firewall guardian failed; see its stderr");
    }
}

impl Drop for Guardian {
    fn drop(&mut self) {
        if !self.dead {
            let mut blocked = self.last.clone();
            blocked.block();
            if let Err(error) = self.apply(&blocked) {
                eprintln!("ERROR restoring block: {error:#}");
            }
        }
        self.input.take();
        match self.child.wait() {
            Ok(status) if status.success() => {}
            result => eprintln!("Guardian exit: {result:?}"),
        }
    }
}

fn send_guardian_error(error: &anyhow::Error) {
    let summary = format!("{error:#}").replace(['\r', '\n'], " ");
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "ERR {summary}");
    let _ = stdout.flush();
}

fn guard() -> Result<()> {
    let result = guard_inner();
    if let Err(ref error) = result {
        send_guardian_error(error);
    }
    result
}

fn guard_inner() -> Result<()> {
    require_root()?;
    let _lock = firewall::lock()?;
    // Terminal signals reach both processes; the parent closes IPC after cleanup.
    ctrlc::set_handler(|| {})?;
    firewall::prepare()?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut policy = Policy::default();
    loop {
        match rx.recv_timeout(Duration::from_secs(LEASE_SECONDS)) {
            Ok(line) => {
                let update =
                    line.and_then(|line| Policy::parse(&line).map_err(std::io::Error::other));
                match update {
                    Ok(update) => {
                        // Never forget known destinations during this session.
                        policy.addresses.extend(update.addresses);
                        policy.allow4 = update.allow4;
                        policy.allow6 = update.allow6;
                    }
                    Err(error) => {
                        policy.block();
                        firewall::apply(&policy)?;
                        return Err(error.into());
                    }
                }
                if let Err(error) = firewall::apply(&policy) {
                    policy.block();
                    if let Err(block_error) = firewall::apply(&policy) {
                        eprintln!("ERROR: emergency block also failed: {block_error:#}");
                    }
                    return Err(error);
                }
                println!("OK");
                std::io::stdout().flush()?;
            }
            Err(error) => {
                policy.block();
                firewall::apply(&policy)?;
                eprintln!("Guardian: no heartbeat; known destinations BLOCKED");
                if error == mpsc::RecvTimeoutError::Disconnected {
                    return Ok(());
                }
            }
        }
    }
}

fn monitor_inner(
    options: NetworkOptions,
    interval: u64,
    extra: Vec<String>,
    mut control: Option<&mut Control>,
) -> Result<()> {
    require_root()?;
    let baseline = options.state.as_deref().map(read_baseline).transpose()?;
    let running = Arc::new(AtomicBool::new(true));
    let stop = running.clone();
    ctrlc::set_handler(move || stop.store(false, Ordering::SeqCst))?;
    let mut guardian = Guardian::start()?;
    let mut policy = Policy::default();
    let mut status = NetworkStatus::default();
    let mut last_error: Option<String> = None;
    let mut last_v4_error: Option<String> = None;
    let mut last_v6_error: Option<String> = None;
    let domains: BTreeSet<_> = DEFAULT_DOMAINS
        .iter()
        .map(|host| host.to_string())
        .chain(extra)
        .collect();
    let other_domains: BTreeSet<_> = OTHER_AI_DOMAINS
        .iter()
        .map(|host| host.to_string())
        .filter(|host| !domains.contains(host))
        .collect();
    guardian.apply(&policy)?;
    report(&mut control, &policy, &status)?;
    let active = |control: &Option<&mut Control>| {
        running.load(Ordering::SeqCst) && control.as_ref().is_none_or(|c| c.running())
    };
    while active(&control) {
        let (addresses, dns_ok) = resolve_domains(&domains, &other_domains)?;
        policy.addresses.extend(addresses);
        if !active(&control) {
            break;
        }
        if !dns_ok {
            policy.block();
        }
        let interface = baseline
            .is_none()
            .then(|| network::direct_interface(options.direct_interface.as_deref()));
        status.interface = interface
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .cloned();
        let mut errors = Vec::new();
        if !dns_ok {
            errors.push("DNS check failed".to_string());
        }
        if let Some(Err(error)) = &interface {
            errors.push(format!("Original IP unknown: {error:#}"));
            policy.block();
            status.ipv4 = FamilyStatus::default();
            status.ipv6 = FamilyStatus::default();
        }
        status.error = (!errors.is_empty()).then(|| errors.join("; "));
        if status.error != last_error {
            if let Some(error) = &status.error {
                eprintln!("{error}");
            }
            last_error = status.error.clone();
        }
        guardian.apply(&policy)?;
        report(&mut control, &policy, &status)?;
        let check = |ipv6| {
            if let Some(baseline) = &baseline {
                let original = if ipv6 {
                    baseline
                        .v6
                        .map(IpAddr::V6)
                        .context("No saved IPv6 baseline")
                } else {
                    Ok(IpAddr::V4(baseline.v4))
                };
                FamilyStatus::from_checks(original, network::public_ip(ipv6, None))
            } else {
                let direct = interface
                    .as_ref()
                    .context("Missing direct-interface selection")
                    .and_then(|value| {
                        value
                            .as_deref()
                            .map_err(|error| anyhow::anyhow!("{error:#}"))
                    });
                network::live_check(ipv6, direct)
            }
        };
        status.ipv4 = check(false);
        if status.ipv4.error != last_v4_error {
            if let Some(error) = &status.ipv4.error {
                eprintln!("IPv4: {error}");
            }
            last_v4_error = status.ipv4.error.clone();
        }
        policy.allow4 = dns_ok && status.ipv4.changed();
        guardian.apply(&policy)?;
        report(&mut control, &policy, &status)?;
        if !active(&control) {
            break;
        }
        status.ipv6 = check(true);
        if status.ipv6.error != last_v6_error {
            if let Some(error) = &status.ipv6.error {
                eprintln!("IPv6: {error}");
            }
            last_v6_error = status.ipv6.error.clone();
        }
        policy.allow6 = dns_ok && status.ipv6.changed();
        if !active(&control) {
            break;
        }
        guardian.apply(&policy)?;
        report(&mut control, &policy, &status)?;
        for _ in 0..interval * 10 {
            if !active(&control) {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    drop(guardian);
    if let Some(control) = control.as_mut() {
        if control.quit_requested() {
            let _lock = firewall::lock()?;
            firewall::uninstall()?;
            control.send(&Message::Stopped)?;
        }
    }
    Ok(())
}

fn monitor(
    options: NetworkOptions,
    interval: u64,
    extra: Vec<String>,
    socket: Option<PathBuf>,
) -> Result<()> {
    require_root()?;
    let mut control = socket.as_deref().map(Control::connect).transpose()?;
    let result = monitor_inner(options, interval, extra, control.as_mut());
    if let (Err(error), Some(control)) = (&result, &mut control) {
        if let Err(send_error) = control.send(&Message::Failure {
            message: format!("{error:#}"),
        }) {
            eprintln!("Cannot report error to tray: {send_error:#}");
        }
    }
    result
}

fn report(
    control: &mut Option<&mut Control>,
    policy: &Policy,
    network: &NetworkStatus,
) -> Result<()> {
    if let Some(control) = control.as_mut() {
        control.send(&Message::Status {
            allow4: policy.allow4,
            allow6: policy.allow6,
            addresses: policy.addresses.len(),
            network: network.clone(),
        })?;
    } else {
        eprintln!(
            "{}; {}; IPv4 {}; IPv6 {}; {} known destinations",
            network.ipv4.label("IPv4"),
            network.ipv6.label("IPv6"),
            if policy.allow4 { "ALLOWED" } else { "BLOCKED" },
            if policy.allow6 { "ALLOWED" } else { "BLOCKED" },
            policy.addresses.len()
        );
    }
    Ok(())
}

fn main() {
    let result = match Cli::parse().command {
        Action::Baseline { state, ipv6 } => record_baseline(&state, ipv6),
        Action::Run {
            network,
            interval,
            domain,
            control,
        } => monitor(network, interval, domain, control),
        Action::Uninstall { if_present } => require_root().and_then(|_| {
            let _lock = firewall::lock()?;
            if if_present {
                return firewall::uninstall_if_present();
            }
            firewall::uninstall()
        }),
        Action::Guard => guard(),
        Action::DesktopHelper { control } => desktop_helper(control),
    };
    if let Err(error) = result {
        eprintln!("ERROR: {error:#}");
        std::process::exit(1);
    }
}

fn desktop_helper(control: PathBuf) -> Result<()> {
    require_root()?;
    let uid: u32 = std::env::var("SUDO_UID")
        .context("Desktop helper must be started by sudo from the desktop account")?
        .parse()
        .context("Invalid SUDO_UID")?;
    if uid == 0 {
        bail!("Desktop helper requires a non-root invoking user");
    }
    validate_desktop_socket(&control, uid)?;
    monitor(NetworkOptions::default(), 2, Vec::new(), Some(control))
}

fn validate_desktop_socket(path: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    if !path.is_absolute() || path.file_name() != Some(std::ffi::OsStr::new("control.sock")) {
        bail!("Expected an absolute path to the tray's control.sock");
    }
    let parent = path.parent().context("Missing socket directory")?;
    if parent.canonicalize()? != parent {
        bail!("Control directory must be canonical and must not contain symlinks");
    }
    let directory = fs::symlink_metadata(parent)?;
    if !directory.is_dir() || directory.uid() != uid || directory.mode() & 0o777 != 0o700 {
        bail!("Control directory must be owned by the invoking user with mode 0700");
    }
    let socket = fs::symlink_metadata(path)?;
    if !socket.file_type().is_socket() || socket.uid() != uid {
        bail!("Control socket must be owned by the invoking user and not be a symlink");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_roundtrip_and_invalid_input() {
        let baseline = Baseline {
            v4: "198.51.100.2".parse().unwrap(),
            v6: Some("2001:db8::2".parse().unwrap()),
        };
        assert_eq!(Baseline::parse(&baseline.encode()).unwrap(), baseline);
        assert!(Baseline::parse("antiban-v1\n::1\n-\n").is_err());
        assert!(Baseline::parse("antiban-v1\n198.51.100.2\n-\nextra").is_err());
        assert!(Baseline::parse("unknown\n198.51.100.2\n-\n").is_err());
    }

    #[test]
    fn policy_roundtrip_including_empty_and_block() {
        assert_eq!(
            Policy::parse(&Policy::default().encode()).unwrap(),
            Policy::default()
        );
        let mut policy = Policy {
            addresses: [
                "198.51.100.8".parse().unwrap(),
                "2001:db8::8".parse().unwrap(),
            ]
            .into(),
            allow4: true,
            allow6: true,
        };
        assert_eq!(Policy::parse(&policy.encode()).unwrap(), policy);
        policy.block();
        assert!(!policy.allow4 && !policy.allow6);
        assert_eq!(policy.addresses.len(), 2);
        assert!(Policy::parse("1 0 1.2.3.4; drop").is_err());
        assert!(Policy::parse("2 0 1.2.3.4").is_err());
    }

    #[test]
    fn domain_lists_are_valid_and_disjoint() {
        let all: Vec<_> = DEFAULT_DOMAINS.iter().chain(OTHER_AI_DOMAINS).collect();
        let unique: BTreeSet<_> = all.iter().collect();
        assert_eq!(unique.len(), all.len(), "duplicate hostname");
        for host in all {
            assert_eq!(domain(host).as_deref(), Ok(*host));
        }
    }

    #[test]
    fn validates_exact_domains() {
        assert_eq!(domain("API.Anthropic.com").unwrap(), "api.anthropic.com");
        for bad in [
            "https://claude.ai",
            "*.claude.ai",
            "a..com",
            "-a.com",
            "a.com\n",
            "a;.com",
        ] {
            assert!(domain(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn restricted_helper_rejects_monitor_options_and_other_commands() {
        assert!(
            Cli::try_parse_from(["agoc", "desktop-helper", "--control", "/tmp/control.sock"])
                .is_ok()
        );
        for flag in ["--state", "--direct-interface", "--domain", "--interval"] {
            assert!(Cli::try_parse_from([
                "agoc",
                "desktop-helper",
                "--control",
                "/tmp/control.sock",
                flag,
                "x"
            ])
            .is_err());
        }
        assert!(Cli::try_parse_from(["agoc", "desktop-helper", "uninstall"]).is_err());
    }

    #[test]
    fn restricted_helper_validates_socket_ownership_permissions_and_symlinks() {
        use std::os::unix::{
            fs::{symlink, MetadataExt, PermissionsExt},
            net::UnixListener,
        };
        let directory = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("agoc-helper-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let uid = fs::metadata(&directory).unwrap().uid();
        assert!(validate_desktop_socket(&socket, uid).is_ok());
        assert!(validate_desktop_socket(&socket, uid + 1).is_err());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_desktop_socket(&socket, uid).is_err());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        drop(listener);
        fs::remove_file(&socket).unwrap();
        let target = directory.join("other.sock");
        let listener = UnixListener::bind(&target).unwrap();
        symlink(&target, &socket).unwrap();
        assert!(validate_desktop_socket(&socket, uid).is_err());
        fs::remove_file(&socket).unwrap();
        drop(listener);
        fs::remove_file(target).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
