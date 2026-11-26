pub mod control;
pub mod network;
#[cfg(windows)]
pub mod windows;

pub fn executable(candidates: &[&str]) -> anyhow::Result<std::path::PathBuf> {
    use anyhow::Context;
    candidates
        .iter()
        .map(std::path::PathBuf::from)
        .find(|path| path.is_file())
        .with_context(|| format!("Required executable not found: {}", candidates.join(", ")))
}

/// Whether this process may change the system firewall: root on Unix, an
/// elevated administrator token on Windows.
pub fn is_privileged() -> anyhow::Result<bool> {
    #[cfg(unix)]
    {
        let output = std::process::Command::new("/usr/bin/id")
            .arg("-u")
            .output()?;
        Ok(output.status.success() && output.stdout == b"0\n")
    }
    #[cfg(windows)]
    {
        windows::is_elevated()
    }
}

#[cfg(feature = "tray")]
pub mod tray;
