#[cfg(any(target_os = "linux", test))]
use crate::LEASE_SECONDS;
use crate::{executable, Policy};
use anyhow::{bail, Context, Result};
#[cfg(any(target_os = "macos", test))]
use std::collections::BTreeSet;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    process::{Command, Stdio},
};
#[cfg(any(target_os = "macos", test))]
use std::net::IpAddr;
#[cfg(target_os = "macos")]
use std::sync::Mutex;

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
    let file = options.open("/var/run/agoc.lock")?;
    file.try_lock()
        .context("Another agoc guardian/uninstall is running; stop it first")?;
    Ok(file)
}

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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn prepare() -> Result<()> {
    bail!("Only Linux and macOS are supported")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn apply(_: &Policy) -> Result<()> {
    bail!("Only Linux and macOS are supported")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn uninstall() -> Result<()> {
    bail!("Only Linux and macOS are supported")
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
