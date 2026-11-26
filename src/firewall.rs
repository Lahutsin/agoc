#[cfg(unix)]
use crate::executable;
use crate::Policy;
#[cfg(any(target_os = "linux", test))]
use crate::LEASE_SECONDS;
use anyhow::{bail, Context, Result};
#[cfg(any(target_os = "macos", windows, test))]
use std::collections::BTreeSet;
#[cfg(unix)]
use std::io::Write;
#[cfg(any(target_os = "macos", windows, test))]
use std::net::IpAddr;
#[cfg(any(target_os = "macos", windows))]
use std::sync::Mutex;
use std::{
    fs::{File, OpenOptions},
    process::{Command, Stdio},
};

#[cfg(target_os = "macos")]
const PF_TOKEN_PATH: &str = "/var/run/agoc.pf-token";

#[cfg(target_os = "macos")]
static LAST_APPLIED: Mutex<Option<Policy>> = Mutex::new(None);

pub(crate) fn lock() -> Result<File> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    options.mode(0o600);
    #[cfg(unix)]
    let path = std::path::PathBuf::from("/var/run/agoc.lock");
    #[cfg(windows)]
    let path = agoc::windows::secure_data_directory()?.join("agoc.lock");
    let file = options.open(path)?;
    file.try_lock()
        .context("Another agoc guardian/uninstall is running; stop it first")?;
    Ok(file)
}

#[cfg(unix)]
fn execute_output(
    program: &std::path::Path,
    args: &[&str],
    input: &str,
) -> Result<(String, String)> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Cannot start {}", program.display()))?;
    let write_result = child
        .stdin
        .take()
        .context("No firewall stdin")?
        .write_all(input.as_bytes());
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "{} failed: {}",
            program.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    write_result?;
    Ok((
        String::from_utf8(output.stdout)?,
        String::from_utf8(output.stderr)?,
    ))
}

#[cfg(unix)]
fn execute(program: &std::path::Path, args: &[&str], input: &str) -> Result<String> {
    Ok(execute_output(program, args, input)?.0)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn nft_rules(policy: &Policy) -> String {
    let mut rules = String::from("delete table inet agoc\ntable inet agoc {\n");
    for (family, ipv6, allowed) in [("4", false, policy.allow4), ("6", true, policy.allow6)] {
        let addresses: Vec<_> = policy
            .addresses
            .iter()
            .filter(|ip| ip.is_ipv6() == ipv6)
            .map(ToString::to_string)
            .collect();
        let kind = if ipv6 { "ipv6_addr" } else { "ipv4_addr" };
        rules.push_str(&format!("set protected{family} {{ type {kind};"));
        if !addresses.is_empty() {
            rules.push_str(&format!(" elements = {{ {} }};", addresses.join(", ")));
        }
        rules.push_str(" }\n");
        rules.push_str(&format!(
            "set allowed{family} {{ type {kind}; flags timeout;"
        ));
        if allowed && !addresses.is_empty() {
            let elements: Vec<_> = addresses
                .iter()
                .map(|ip| format!("{ip} timeout {LEASE_SECONDS}s"))
                .collect();
            rules.push_str(&format!(" elements = {{ {} }};", elements.join(", ")));
        }
        rules.push_str(" }\n");
    }
    let protected = "ip daddr @protected4 ip daddr != @allowed4 counter drop\n\
         ip6 daddr @protected6 ip6 daddr != @allowed6 counter drop\n";
    rules.push_str("chain output {\n type filter hook output priority -10; policy accept;\n");
    rules.push_str(protected);
    rules.push_str("}\n");
    // Forwarded traffic: containers and VMs routed through this host.
    rules.push_str("chain forward {\n type filter hook forward priority -10; policy accept;\n");
    rules.push_str(protected);
    rules.push_str("}\n}\n");
    rules
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn pf_rules(policy: &Policy) -> String {
    let mut rules = String::new();
    for (family, ipv6) in [("4", false), ("6", true)] {
        let addresses: Vec<_> = policy
            .addresses
            .iter()
            .filter(|ip| ip.is_ipv6() == ipv6)
            .map(ToString::to_string)
            .collect();
        rules.push_str(&format!(
            "table <agoc{family}> persist {{ {} }}\n",
            addresses.join(", ")
        ));
    }
    for (family, ipv6, allowed) in [("4", false, policy.allow4), ("6", true, policy.allow6)] {
        if !allowed {
            let inet = if ipv6 { "inet6" } else { "inet" };
            rules.push_str(&format!(
                "block drop out quick {inet} from any to <agoc{family}>\n"
            ));
        }
    }
    rules
}

#[cfg(target_os = "linux")]
pub(crate) fn prepare() -> Result<()> {
    let nft = executable(&["/usr/sbin/nft", "/sbin/nft"])?;
    execute(&nft, &["-f", "-"], "add table inet agoc\n")?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn apply(policy: &Policy) -> Result<()> {
    let nft = executable(&["/usr/sbin/nft", "/sbin/nft"])?;
    execute(&nft, &["-f", "-"], &nft_rules(policy))?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn uninstall() -> Result<()> {
    let nft = executable(&["/usr/sbin/nft", "/sbin/nft"])?;
    execute(&nft, &["-f", "-"], "delete table inet agoc\n")?;
    Ok(())
}

pub(crate) fn uninstall_if_present() -> Result<()> {
    #[cfg(windows)]
    {
        let netsh = netsh()?;
        if !WINDOWS_RULES.iter().any(|name| rule_exists(&netsh, name)) {
            eprintln!("AGOC firewall rules are already absent");
            return Ok(());
        }
    }
    #[cfg(target_os = "linux")]
    {
        let nft = executable(&["/usr/sbin/nft", "/sbin/nft"])?;
        let tables = execute(&nft, &["list", "tables"], "")?;
        if !tables.lines().any(|line| line.trim() == "table inet agoc") {
            eprintln!("AGOC firewall table is already absent");
            return Ok(());
        }
    }
    #[cfg(target_os = "macos")]
    {
        let pf = executable(&["/sbin/pfctl"])?;
        let has_rules = !execute(&pf, &["-a", "agoc", "-sr"], "")
            .unwrap_or_default()
            .trim()
            .is_empty();
        let has_tables = !execute(&pf, &["-a", "agoc", "-sT"], "")
            .unwrap_or_default()
            .trim()
            .is_empty();
        let has_token = std::path::Path::new(PF_TOKEN_PATH).exists();
        if !has_rules && !has_tables && !has_token {
            eprintln!("AGOC PF rules are already absent");
            return Ok(());
        }
    }
    uninstall()
}

#[cfg(any(target_os = "macos", test))]
fn parse_pf_token(output: &str) -> Option<String> {
    for line in output.lines() {
        if let Some(rest) = line.trim().strip_prefix("Token") {
            if let Some(token) = rest.trim_start().strip_prefix(':') {
                let token = token.trim();
                if !token.is_empty() && token.bytes().all(|b| b.is_ascii_digit()) {
                    return Some(token.to_owned());
                }
            }
        }
    }
    None
}

#[cfg(any(target_os = "macos", test))]
fn validate_pf_rules(rules: &str) -> Result<()> {
    for raw in rules.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("scrub ") || line.starts_with("scrub-anchor ") {
            continue;
        }
        if line == "anchor \"agoc\" all" || line == "anchor \"agoc\"" {
            return Ok(());
        }
        if line == "anchor \"com.apple/*\" all" || line == "anchor \"com.apple/*\"" {
            continue;
        }
        bail!("PF filter rule before anchor \"agoc\" may bypass blocking: {line}");
    }
    bail!("Active PF ruleset is missing anchor \"agoc\"; add it to /etc/pf.conf and reload PF (see README)");
}

#[cfg(any(target_os = "macos", test))]
fn ips_to_kill(previous: Option<&Policy>, current: &Policy) -> BTreeSet<IpAddr> {
    let mut kill = BTreeSet::new();
    for &ip in &current.addresses {
        let blocked = if ip.is_ipv4() {
            !current.allow4
        } else {
            !current.allow6
        };
        if !blocked {
            continue;
        }
        let needs_kill = match previous {
            None => true,
            Some(prev) => {
                let was_allowed = if ip.is_ipv4() {
                    prev.allow4
                } else {
                    prev.allow6
                };
                was_allowed || !prev.addresses.contains(&ip)
            }
        };
        if needs_kill {
            kill.insert(ip);
        }
    }
    kill
}

#[cfg(target_os = "macos")]
fn read_pf_token() -> Option<String> {
    let content = std::fs::read_to_string(PF_TOKEN_PATH).ok()?;
    let token = content.trim();
    (!token.is_empty() && token.bytes().all(|b| b.is_ascii_digit())).then(|| token.to_owned())
}

#[cfg(target_os = "macos")]
fn write_pf_token(token: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(PF_TOKEN_PATH);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(PF_TOKEN_PATH)
        .with_context(|| format!("Cannot create {PF_TOKEN_PATH}"))?;
    writeln!(file, "{token}")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn pf_has_reference(pf: &std::path::Path, token: &str) -> bool {
    execute(pf, &["-s", "References"], "")
        .ok()
        .is_some_and(|refs| {
            refs.lines()
                .any(|line| line.split_whitespace().any(|word| word == token))
        })
}

#[cfg(target_os = "macos")]
fn ensure_pf_enabled(pf: &std::path::Path) -> Result<()> {
    let status = execute(pf, &["-s", "info"], "")?;
    let enabled = status
        .lines()
        .any(|line| line.starts_with("Status: Enabled"));
    if enabled {
        if let Some(token) = read_pf_token() {
            if pf_has_reference(pf, &token) {
                return Ok(());
            }
        }
    }
    let (stdout, stderr) = execute_output(pf, &["-E"], "")?;
    let combined = format!("{stdout}\n{stderr}");
    if let Some(token) = parse_pf_token(&combined) {
        write_pf_token(&token)?;
    }
    let status = execute(pf, &["-s", "info"], "")?;
    if !status
        .lines()
        .any(|line| line.starts_with("Status: Enabled"))
    {
        bail!("Cannot enable PF with pfctl -E");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn prepare() -> Result<()> {
    *LAST_APPLIED.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let pf = executable(&["/sbin/pfctl"])?;
    ensure_pf_enabled(&pf)?;
    let rules = execute(&pf, &["-sr"], "")?;
    validate_pf_rules(&rules)?;
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn apply(policy: &Policy) -> Result<()> {
    let pf = executable(&["/sbin/pfctl"])?;
    execute(&pf, &["-a", "agoc", "-f", "-"], &pf_rules(policy))?;
    let mut guard = LAST_APPLIED.lock().unwrap_or_else(|e| e.into_inner());
    let kill = ips_to_kill(guard.as_ref(), policy);
    // PF checks existing states before rules. Kill states for newly blocked or newly added IPs.
    for ip in kill {
        let any = if ip.is_ipv4() { "0.0.0.0/0" } else { "::/0" };
        execute(&pf, &["-k", any, "-k", &ip.to_string()], "")?;
    }
    *guard = Some(policy.clone());
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn uninstall() -> Result<()> {
    *LAST_APPLIED.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let pf = executable(&["/sbin/pfctl"])?;
    execute(&pf, &["-a", "agoc", "-F", "all"], "")?;
    if let Some(token) = read_pf_token() {
        let _ = std::fs::remove_file(PF_TOKEN_PATH);
        if let Err(error) = execute(&pf, &["-X", &token], "") {
            eprintln!("Note: pfctl -X {token}: {error:#}");
        }
    }
    Ok(())
}

// Windows: block rules in Windows Defender Firewall, managed with netsh.
//
// Each family uses two alternating rule names ("generations"). A changed
// address set is first added under the unused name and only then is the old
// name deleted, so updates never open a gap. One name may hold several rules
// (chunks); `netsh delete rule name=...` removes all of them. netsh output is
// localized, so only exit codes are evaluated.

/// Rule names, per family: [IPv4 A, IPv4 B, IPv6 A, IPv6 B].
#[cfg(any(windows, test))]
const WINDOWS_RULES: [&str; 4] = ["AGOC-IPv4-A", "AGOC-IPv4-B", "AGOC-IPv6-A", "AGOC-IPv6-B"];

/// Addresses per firewall rule; keeps each netsh command line short.
#[cfg(any(windows, test))]
const ADDRESSES_PER_RULE: usize = 100;

#[cfg(windows)]
#[derive(Default, Clone)]
struct WindowsFamily {
    /// Index (0/1) of the rule name currently holding the block, if any.
    generation: Option<usize>,
    blocked: BTreeSet<IpAddr>,
}

#[cfg(windows)]
static WINDOWS_STATE: Mutex<Option<[WindowsFamily; 2]>> = Mutex::new(None);

/// `netsh add rule` argument lists blocking `addresses` under `name`.
#[cfg(any(windows, test))]
fn windows_rule_arguments(name: &str, addresses: &BTreeSet<IpAddr>) -> Vec<Vec<String>> {
    let addresses: Vec<_> = addresses.iter().map(ToString::to_string).collect();
    addresses
        .chunks(ADDRESSES_PER_RULE)
        .map(|chunk| {
            [
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={name}"),
                "dir=out",
                "action=block",
                "enable=yes",
                "profile=any",
                "protocol=any",
                &format!("remoteip={}", chunk.join(",")),
                "description=AGOC-managed",
            ]
            .map(String::from)
            .to_vec()
        })
        .collect()
}

/// Problems in `Get-NetFirewallProfile` output ("<Name> <Enabled> <AllowLocalFirewallRules>"
/// per line) that would make the AGOC rules ineffective.
#[cfg(any(windows, test))]
fn windows_profile_problems(output: &str) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    let mut profiles = 0;
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let [name, enabled, local] = fields[..] else {
            bail!("Unexpected firewall profile output: {line}");
        };
        profiles += 1;
        if !enabled.eq_ignore_ascii_case("True") {
            problems.push(format!("the {name} profile is turned off"));
        }
        if local.eq_ignore_ascii_case("False") {
            problems.push(format!(
                "Group Policy ignores local firewall rules in the {name} profile"
            ));
        }
    }
    if profiles == 0 {
        bail!("No Windows Firewall profiles found");
    }
    Ok(problems)
}

#[cfg(windows)]
fn netsh() -> Result<std::path::PathBuf> {
    let path = agoc::windows::system_directory()?.join("netsh.exe");
    if !path.is_file() {
        bail!("Required executable not found: {}", path.display());
    }
    Ok(path)
}

/// Runs a system tool with an environment that cannot redirect it to
/// user-controlled files (the caller is elevated, the environment is not).
#[cfg(windows)]
fn windows_command(program: &std::path::Path) -> Result<Command> {
    let windows = agoc::windows::windows_directory()?;
    let system = agoc::windows::system_directory()?;
    let mut command = Command::new(program);
    command
        .env("SystemRoot", &windows)
        .env("windir", &windows)
        .env("PATH", &system)
        .env(
            "PSModulePath",
            system.join(r"WindowsPowerShell\v1.0\Modules"),
        )
        .env_remove("PSExecutionPolicyPreference")
        .stdin(Stdio::null());
    Ok(command)
}

#[cfg(windows)]
fn windows_run(program: &std::path::Path, args: &[String]) -> Result<String> {
    let output = windows_command(program)?
        .args(args)
        .output()
        .with_context(|| format!("Cannot start {}", program.display()))?;
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).trim().to_string();
    if !output.status.success() {
        bail!(
            "{} {} failed ({}): {} {}",
            program.display(),
            args.iter().take(4).cloned().collect::<Vec<_>>().join(" "),
            output.status,
            text(&output.stdout),
            text(&output.stderr)
        );
    }
    Ok(text(&output.stdout))
}

#[cfg(windows)]
fn rule_exists(netsh: &std::path::Path, name: &str) -> bool {
    windows_command(netsh)
        .and_then(|mut command| {
            Ok(command
                .args(["advfirewall", "firewall", "show", "rule"])
                .arg(format!("name={name}"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?)
        })
        .is_ok_and(|status| status.success())
}

#[cfg(windows)]
fn delete_rule(netsh: &std::path::Path, name: &str) -> Result<()> {
    if rule_exists(netsh, name) {
        windows_run(
            netsh,
            &[
                "advfirewall".into(),
                "firewall".into(),
                "delete".into(),
                "rule".into(),
                format!("name={name}"),
            ],
        )?;
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn prepare() -> Result<()> {
    *WINDOWS_STATE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    netsh()?;
    let powershell =
        agoc::windows::system_directory()?.join(r"WindowsPowerShell\v1.0\powershell.exe");
    let output = windows_run(
        &powershell,
        &[
            "-NoLogo".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            "$ErrorActionPreference = 'Stop'; Get-NetFirewallProfile -PolicyStore ActiveStore | \
             ForEach-Object { '{0} {1} {2}' -f $_.Name, $_.Enabled, $_.AllowLocalFirewallRules }"
                .into(),
        ],
    )
    .context("Cannot read the Windows Firewall state")?;
    let problems = windows_profile_problems(&output)?;
    if !problems.is_empty() {
        bail!(
            "Windows Defender Firewall would not enforce AGOC rules: {}. \
             Turn the firewall on for all profiles (see README)",
            problems.join("; ")
        );
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn apply(policy: &Policy) -> Result<()> {
    let netsh = netsh()?;
    let mut guard = WINDOWS_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        // Start from a clean state: leftovers of an earlier session are unknown.
        for name in WINDOWS_RULES {
            delete_rule(&netsh, name)?;
        }
        *guard = Some(Default::default());
    }
    let families = guard.as_mut().context("Missing firewall state")?;
    for (slot, ipv6, allowed) in [(0, false, policy.allow4), (1, true, policy.allow6)] {
        let names = [WINDOWS_RULES[slot * 2], WINDOWS_RULES[slot * 2 + 1]];
        let family = &mut families[slot];
        let wanted: BTreeSet<IpAddr> = if allowed {
            BTreeSet::new()
        } else {
            policy
                .addresses
                .iter()
                .copied()
                .filter(|ip| ip.is_ipv6() == ipv6)
                .collect()
        };
        if family.generation.is_some() == !wanted.is_empty() && family.blocked == wanted {
            continue;
        }
        if wanted.is_empty() {
            // Both names: a failed earlier update may have left partial rules.
            for name in names {
                delete_rule(&netsh, name)?;
            }
            *family = WindowsFamily::default();
            continue;
        }
        let next = family.generation.map_or(0, |current| 1 - current);
        delete_rule(&netsh, names[next])?;
        for arguments in windows_rule_arguments(names[next], &wanted) {
            windows_run(&netsh, &arguments)?;
        }
        if let Some(current) = family.generation {
            delete_rule(&netsh, names[current])?;
        }
        *family = WindowsFamily {
            generation: Some(next),
            blocked: wanted,
        };
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn uninstall() -> Result<()> {
    *WINDOWS_STATE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let netsh = netsh()?;
    for name in WINDOWS_RULES {
        delete_rule(&netsh, name)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Policy {
        Policy {
            addresses: [
                "198.51.100.8".parse().unwrap(),
                "2001:db8::8".parse().unwrap(),
            ]
            .into(),
            allow4: true,
            allow6: false,
        }
    }

    #[test]
    fn nft_also_filters_forwarded_container_and_vm_traffic() {
        let rules = nft_rules(&sample());
        // Containers/VMs routed through this host are covered too.
        let forward = &rules[rules.find("chain forward").unwrap()..];
        assert!(forward.contains("ip daddr @protected4 ip daddr != @allowed4 counter drop"));
    }

    #[test]
    fn nft_has_family_specific_expiring_permissions_and_output_drops() {
        let rules = nft_rules(&sample());
        assert!(rules.contains("198.51.100.8 timeout 30s"));
        assert!(!rules.contains("2001:db8::8 timeout"));
        assert!(rules.contains("ip daddr @protected4 ip daddr != @allowed4 counter drop"));
        assert!(rules.contains("ip6 daddr @protected6 ip6 daddr != @allowed6 counter drop"));
        assert!(rules.starts_with("delete table inet agoc\n"));
    }

    #[test]
    fn pf_blocks_only_disabled_family() {
        let rules = pf_rules(&sample());
        assert!(!rules.contains("block drop out quick inet from"));
        assert!(rules.contains("block drop out quick inet6 from any to <agoc6>"));
        assert!(rules.contains("table <agoc4> persist { 198.51.100.8 }"));
        assert!(rules.contains("table <agoc6> persist { 2001:db8::8 }"));
    }

    #[test]
    fn blocked_rules_have_no_permissions() {
        let mut policy = sample();
        policy.block();
        assert!(!nft_rules(&policy).contains("timeout 30s"));
        assert_eq!(pf_rules(&policy).matches("block drop out quick").count(), 2);
    }

    #[test]
    fn windows_rules_block_each_family_in_short_chunks() {
        let addresses: BTreeSet<IpAddr> = (0..250u32)
            .map(|i| IpAddr::V4(std::net::Ipv4Addr::from(0xc633_6400 + i)))
            .collect();
        let rules = windows_rule_arguments("AGOC-IPv4-A", &addresses);
        assert_eq!(rules.len(), 3);
        for rule in &rules {
            for expected in ["name=AGOC-IPv4-A", "dir=out", "action=block", "profile=any"] {
                assert!(rule.iter().any(|arg| arg == expected), "{expected}");
            }
            // netsh splits on spaces; no argument may contain one.
            assert!(rule.iter().all(|arg| !arg.contains(' ')));
        }
        assert!(rules[0][10].starts_with("remoteip=198.51.100.0,198.51.100.1,"));
        let total: usize = rules
            .iter()
            .map(|rule| rule[10].trim_start_matches("remoteip=").split(',').count())
            .sum();
        assert_eq!(total, 250);
        assert!(windows_rule_arguments("AGOC-IPv4-A", &BTreeSet::new()).is_empty());
        assert_eq!(WINDOWS_RULES.len(), 4);
    }

    #[test]
    fn windows_firewall_must_be_on_and_honor_local_rules() {
        let all_on = "Domain True NotConfigured\nPrivate True True\nPublic True NotConfigured\n";
        assert!(windows_profile_problems(all_on).unwrap().is_empty());
        let problems =
            windows_profile_problems("Domain False False\nPrivate True True\nPublic True False\n")
                .unwrap();
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(problems[0].contains("Domain profile is turned off"));
        assert!(windows_profile_problems("").is_err());
        assert!(windows_profile_problems("Domain True").is_err());
    }

    #[test]
    fn parses_pf_enable_tokens() {
        assert_eq!(
            parse_pf_token("pf enabled\nToken : 12345678901234567\n").as_deref(),
            Some("12345678901234567")
        );
        assert_eq!(parse_pf_token("pf enabled\n"), None);
        assert_eq!(parse_pf_token("Token : not-a-number\n"), None);
    }

    #[test]
    fn validates_pf_anchor_ordering_with_apple_rules() {
        let first = "scrub-anchor \"com.apple/*\" all fragment reassemble\n\
            anchor \"agoc\" all\n\
            anchor \"com.apple/*\" all\n";
        assert!(validate_pf_rules(first).is_ok());

        let after_apple = "scrub-anchor \"com.apple/*\" all fragment reassemble\n\
            anchor \"com.apple/*\" all\n\
            anchor \"agoc\" all\n";
        assert!(validate_pf_rules(after_apple).is_ok());

        let missing = "scrub-anchor \"com.apple/*\" all\nanchor \"com.apple/*\" all\n";
        assert!(validate_pf_rules(missing).is_err());

        let bypassed = "pass out quick all\nanchor \"agoc\" all\n";
        assert!(validate_pf_rules(bypassed).is_err());
    }

    #[test]
    fn kills_states_only_for_newly_blocked_or_new_ips() {
        let ip4a: IpAddr = "198.51.100.8".parse().unwrap();
        let ip4b: IpAddr = "198.51.100.9".parse().unwrap();
        let ip6a: IpAddr = "2001:db8::8".parse().unwrap();

        let p1 = Policy {
            addresses: [ip4a, ip6a].into(),
            allow4: false,
            allow6: false,
        };
        assert_eq!(ips_to_kill(None, &p1), [ip4a, ip6a].into());
        assert!(ips_to_kill(Some(&p1), &p1).is_empty());

        let mut p2 = p1.clone();
        p2.addresses.insert(ip4b);
        assert_eq!(ips_to_kill(Some(&p1), &p2), [ip4b].into());

        let mut p3 = p2.clone();
        p3.allow4 = true;
        assert!(ips_to_kill(Some(&p2), &p3).is_empty());

        let mut p4 = p3.clone();
        p4.allow4 = false;
        assert_eq!(ips_to_kill(Some(&p3), &p4), [ip4a, ip4b].into());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a fresh rootless user/network namespace; see README"]
    fn linux_kernel_gate_and_lease_in_private_namespace() {
        use std::{
            io::Read,
            net::{TcpListener, TcpStream},
            time::Duration,
        };

        let mapping = std::fs::read_to_string("/proc/self/uid_map").unwrap();
        let fields: Vec<_> = mapping.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "Use a fresh rootless user namespace");
        assert_eq!(fields[0], "0");
        assert_ne!(fields[1], "0", "Never run this test in the host namespace");
        assert_eq!(fields[2], "1");
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::path::PathBuf::from(
                std::env::var("AGOC_TEST_HOST_NETNS")
                    .expect("Set AGOC_TEST_HOST_NETNS before unshare; see README")
            ),
            "Use a private network namespace"
        );
        let nft = executable(&["/usr/sbin/nft", "/sbin/nft"]).unwrap();
        assert!(execute(&nft, &["list", "tables"], "").unwrap().is_empty());
        let ip = executable(&["/usr/sbin/ip", "/sbin/ip"]).unwrap();
        execute(&ip, &["link", "set", "lo", "up"], "").unwrap();

        let v4 = TcpListener::bind("127.0.0.3:0").unwrap();
        let v6 = TcpListener::bind("[::1]:0").unwrap();
        let unrelated = TcpListener::bind("127.0.0.2:0").unwrap();
        let connect = |listener: &TcpListener| {
            TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_millis(200))
        };
        let mut policy = Policy {
            addresses: ["127.0.0.3".parse().unwrap(), "::1".parse().unwrap()].into(),
            ..Policy::default()
        };
        prepare().unwrap();
        apply(&policy).unwrap();
        assert!(connect(&v4).is_err());
        assert!(connect(&v6).is_err());
        assert!(connect(&unrelated).is_ok());

        policy.allow4 = true;
        apply(&policy).unwrap();
        let mut client = connect(&v4).unwrap();
        let (mut server, _) = v4.accept().unwrap();
        assert!(connect(&v6).is_err());
        policy.block();
        apply(&policy).unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        client.write_all(b"x").unwrap();
        assert!(
            server.read_exact(&mut [0u8; 1]).is_err(),
            "Established traffic must also be blocked"
        );
        drop(client);
        drop(server);

        policy.allow4 = true;
        policy.allow6 = true;
        apply(&policy).unwrap();
        assert!(connect(&v4).is_ok());
        assert!(connect(&v6).is_ok());
        assert!(connect(&unrelated).is_ok());
        std::thread::sleep(Duration::from_secs(LEASE_SECONDS + 1));
        assert!(
            connect(&v4).is_err(),
            "IPv4 permission must expire in the kernel"
        );
        assert!(
            connect(&v6).is_err(),
            "IPv6 permission must expire in the kernel"
        );
        assert!(connect(&unrelated).is_ok());
        uninstall().unwrap();
        assert!(connect(&v4).is_ok());
        assert!(connect(&v6).is_ok());
    }
}
