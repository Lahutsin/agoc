use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    thread,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Status {
        allow4: bool,
        allow6: bool,
        addresses: usize,
        network: crate::network::NetworkStatus,
    },
    Quit,
    Stopped,
    Failure {
        message: String,
    },
}

/// Tray <-> monitor connection: a Unix socket in a private directory on Linux
/// and macOS; on Windows a loopback TCP connection authenticated by a random
/// token, which the helper sends as its first line.
#[cfg(unix)]
pub type Stream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type Stream = std::net::TcpStream;

/// Length of the hex-encoded Windows control token.
pub const TOKEN_LENGTH: usize = 64;

pub fn valid_token(token: &str) -> bool {
    token.len() == TOKEN_LENGTH && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Compares tokens without an early exit on the first differing byte.
pub fn token_matches(expected: &str, received: &str) -> bool {
    expected.len() == received.len()
        && expected
            .bytes()
            .zip(received.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

#[cfg(unix)]
fn connect_stream(endpoint: &Path, token: Option<&str>) -> Result<Stream> {
    if token.is_some() {
        bail!("Control tokens are only used on Windows");
    }
    Stream::connect(endpoint).context("Cannot connect to tray control socket")
}

#[cfg(windows)]
fn connect_stream(endpoint: &Path, token: Option<&str>) -> Result<Stream> {
    let address: std::net::SocketAddr = endpoint
        .to_str()
        .context("Invalid control endpoint")?
        .parse()
        .context("Expected a loopback control address such as 127.0.0.1:50000")?;
    if !address.ip().is_loopback() {
        bail!("The control endpoint must be a loopback address");
    }
    let token = token
        .filter(|token| valid_token(token))
        .context("Missing or invalid control token")?;
    let mut stream = Stream::connect_timeout(&address, std::time::Duration::from_secs(5))
        .context("Cannot connect to tray control endpoint")?;
    stream.write_all(format!("{token}\n").as_bytes())?;
    stream.flush()?;
    Ok(stream)
}

pub fn send(stream: &mut impl Write, message: &Message) -> Result<()> {
    serde_json::to_writer(&mut *stream, message)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

pub struct Control {
    stream: Stream,
    state: Arc<AtomicU8>,
}

impl Control {
    pub fn connect(endpoint: &Path, token: Option<&str>) -> Result<Self> {
        let stream = connect_stream(endpoint, token)?;
        let input = stream.try_clone()?;
        let state = Arc::new(AtomicU8::new(0));
        let reader_state = state.clone();
        thread::spawn(move || {
            let result = (|| -> Result<()> {
                let mut line = String::new();
                BufReader::new(input).take(4096).read_line(&mut line)?;
                if serde_json::from_str::<Message>(&line)? != Message::Quit {
                    bail!("Expected a Quit control message");
                }
                Ok(())
            })();
            match result {
                Ok(()) => reader_state.store(1, Ordering::SeqCst),
                Err(error) => {
                    eprintln!("Tray control disconnected or invalid: {error:#}");
                    reader_state.store(2, Ordering::SeqCst);
                }
            }
        });
        Ok(Self { stream, state })
    }

    pub fn running(&self) -> bool {
        self.state.load(Ordering::SeqCst) == 0
    }

    pub fn quit_requested(&self) -> bool {
        self.state.load(Ordering::SeqCst) == 1
    }

    pub fn send(&mut self, message: &Message) -> Result<()> {
        send(&mut self.stream, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_hex_and_compared_exactly() {
        let token = "ab".repeat(32);
        assert!(valid_token(&token));
        assert!(!valid_token(&token[1..]));
        assert!(!valid_token(&"zz".repeat(32)));
        assert!(token_matches(&token, &token));
        assert!(!token_matches(&token, &"ab".repeat(31)));
        assert!(!token_matches(&token, &format!("{}ac", "ab".repeat(31))));
    }

    #[cfg(unix)]
    #[test]
    fn status_and_quit_protocol_roundtrip() {
        use std::os::unix::net::UnixStream;
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let message = Message::Status {
            allow4: true,
            allow6: false,
            addresses: 12,
            network: Default::default(),
        };
        send(&mut sender, &message).unwrap();
        let mut line = String::new();
        BufReader::new(receiver).read_line(&mut line).unwrap();
        assert_eq!(serde_json::from_str::<Message>(&line).unwrap(), message);
        assert!(serde_json::from_str::<Message>(r#"{"type":"execute","command":"id"}"#).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn explicit_quit_is_distinct_from_disconnection() {
        use std::os::unix::net::UnixListener;
        let path =
            std::env::temp_dir().join(format!("agoc-control-test-{}.sock", std::process::id()));
        let listener = UnixListener::bind(&path).unwrap();
        let control = Control::connect(&path, None).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        send(&mut peer, &Message::Quit).unwrap();
        for _ in 0..100 {
            if !control.running() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(control.quit_requested());
        drop(control);
        let control = Control::connect(&path, None).unwrap();
        let (peer, _) = listener.accept().unwrap();
        drop(peer);
        for _ in 0..100 {
            if !control.running() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!control.running());
        assert!(!control.quit_requested());
        std::fs::remove_file(path).unwrap();
    }
}
