//! GnuPG side. A vault entry holds a secret key exported from gpg together
//! with the passphrase that protects it. Unlocking imports the key (still
//! protected) when this machine lacks it, then presets that passphrase in
//! gpg-agent, so the single kleyknox passphrase unlocks GPG too. The key on
//! the PC's disk stays useless without the stick.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use ssh_key::rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::platform;

const BUNDLE_MAGIC: &str = "kleyknox-gpg-v1";

pub struct Bundle {
    pub fingerprint: String,
    pub keygrips: Vec<String>,
    pub passphrase: Zeroizing<String>,
    pub secret_armor: Zeroizing<String>,
}

impl Bundle {
    pub fn encode(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(format!("{BUNDLE_MAGIC}\nfingerprint {}\n", self.fingerprint));
        for grip in &self.keygrips {
            out.push_str(&format!("keygrip {grip}\n"));
        }
        out.push_str(&format!("passphrase {}\n\n", self.passphrase.as_str()));
        out.push_str(&self.secret_armor);
        out
    }

    pub fn decode(text: &str) -> Result<Self> {
        let (header, armor) = text.split_once("\n\n").context("malformed GPG entry")?;
        let mut lines = header.lines();
        if lines.next() != Some(BUNDLE_MAGIC) {
            bail!("not a kleyknox GPG entry");
        }
        let mut fingerprint = None;
        let mut keygrips = Vec::new();
        let mut passphrase = Zeroizing::new(String::new());
        for line in lines {
            match line.split_once(' ') {
                Some(("fingerprint", v)) => fingerprint = Some(v.to_owned()),
                Some(("keygrip", v)) => keygrips.push(v.to_owned()),
                Some(("passphrase", v)) => passphrase.push_str(v),
                _ => bail!("malformed GPG entry"),
            }
        }
        Ok(Self {
            fingerprint: fingerprint.context("GPG entry without fingerprint")?,
            keygrips,
            passphrase,
            secret_armor: Zeroizing::new(armor.to_owned()),
        })
    }
}

/// Runs gpg in batch mode; `input` goes to stdin so secrets never reach argv.
fn gpg(args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut child = Command::new("gpg")
        .arg("--batch")
        .args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot run gpg (is GnuPG installed?)")?;
    if let Some(data) = input {
        child.stdin.take().unwrap().write_all(data)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let last = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("unknown error");
        bail!("gpg {}: {}", args.first().unwrap_or(&""), last.trim_start_matches("gpg: "));
    }
    Ok(out.stdout)
}

fn gpgconf(args: &[&str]) -> Result<String> {
    let out = Command::new("gpgconf").args(args).output().context("cannot run gpgconf")?;
    if !out.status.success() {
        bail!("gpgconf {} failed", args.join(" "));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Creates an Ed25519 signing key with a Cv25519 encryption subkey, protected
/// by a random passphrase that only the vault will know.
pub fn generate(uid: &str) -> Result<Bundle> {
    let mut raw = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(raw.as_mut());
    let passphrase = hex(raw.as_ref());
    let stdin = Zeroizing::new(format!("{}\n", passphrase.as_str()));
    let loopback = ["--pinentry-mode", "loopback", "--passphrase-fd", "0"];

    let mut args = vec!["--status-fd", "1"];
    args.extend(loopback);
    args.extend(["--quick-gen-key", uid, "ed25519", "sign,cert", "never"]);
    let status = String::from_utf8_lossy(&gpg(&args, Some(stdin.as_bytes()))?).into_owned();
    let fingerprint = status
        .lines()
        .find_map(|l| l.strip_prefix("[GNUPG:] KEY_CREATED "))
        .and_then(|rest| rest.split_whitespace().nth(1))
        .context("gpg did not report the new key")?
        .to_owned();

    let mut args = loopback.to_vec();
    args.extend(["--quick-add-key", &fingerprint, "cv25519", "encr", "never"]);
    gpg(&args, Some(stdin.as_bytes()))?;

    export(fingerprint, passphrase)
}

/// Bundles a key already in the keyring. `passphrase` is its current one
/// (empty for an unprotected key); a wrong one makes the export fail.
pub fn existing(key_id: &str, passphrase: Zeroizing<String>) -> Result<Bundle> {
    let listing = String::from_utf8_lossy(&gpg(&["--with-colons", "--list-secret-keys", key_id], None)?)
        .into_owned();
    let mut fprs = Vec::new();
    let mut after_sec = false;
    for line in listing.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        match fields.first() {
            Some(&"sec") => after_sec = true,
            Some(&"fpr") if after_sec => {
                fprs.push(fields.get(9).copied().unwrap_or_default().to_owned());
                after_sec = false;
            }
            _ => {}
        }
    }
    match fprs.as_slice() {
        [one] => export(one.clone(), passphrase),
        [] => bail!("no secret key matches {key_id}"),
        _ => bail!("{key_id} matches several secret keys; use the full fingerprint"),
    }
}

fn export(fingerprint: String, passphrase: Zeroizing<String>) -> Result<Bundle> {
    let stdin = Zeroizing::new(format!("{}\n", passphrase.as_str()));
    let armor = Zeroizing::new(
        String::from_utf8(gpg(
            &[
                "--pinentry-mode", "loopback", "--passphrase-fd", "0",
                "--armor", "--export-secret-keys", &fingerprint,
            ],
            Some(stdin.as_bytes()),
        )?)
        .context("gpg exported non-UTF-8 armor")?,
    );
    if armor.is_empty() {
        bail!("gpg exported nothing for {fingerprint}");
    }
    let keygrips = keygrips(&fingerprint)?;
    Ok(Bundle { fingerprint, keygrips, passphrase, secret_armor: armor })
}

fn keygrips(fingerprint: &str) -> Result<Vec<String>> {
    let listing = gpg(&["--with-colons", "--with-keygrip", "--list-secret-keys", fingerprint], None)?;
    Ok(String::from_utf8_lossy(&listing)
        .lines()
        .filter(|l| l.starts_with("grp:"))
        .filter_map(|l| l.split(':').nth(9).map(str::to_owned))
        .collect())
}

pub fn public_armor(fingerprint: &str) -> Result<String> {
    Ok(String::from_utf8(gpg(&["--armor", "--export", fingerprint], None)?)?)
}

/// Imports the protected secret key unless this keyring already has it.
pub fn ensure_imported(bundle: &Bundle) -> Result<bool> {
    if gpg(&["--with-colons", "--list-secret-keys", &bundle.fingerprint], None).is_ok() {
        return Ok(false);
    }
    gpg(&["--import"], Some(bundle.secret_armor.as_bytes()))?;
    Ok(true)
}

/// gpg-agent refuses PRESET_PASSPHRASE unless allowed in its config.
pub fn ensure_preset_allowed() -> Result<bool> {
    let conf = PathBuf::from(gpgconf(&["--list-dirs", "homedir"])?).join("gpg-agent.conf");
    let current = fs::read_to_string(&conf).unwrap_or_default();
    if current.lines().any(|l| l.trim() == "allow-preset-passphrase") {
        return Ok(false);
    }
    let mut f = fs::OpenOptions::new().create(true).append(true).open(&conf)
        .with_context(|| format!("cannot update {}", conf.display()))?;
    if !current.is_empty() && !current.ends_with('\n') {
        f.write_all(b"\n")?;
    }
    f.write_all(b"# added by kleyknox: lets it hand the passphrase to gpg-agent\nallow-preset-passphrase\n")?;
    gpgconf(&["--reload", "gpg-agent"])?;
    Ok(true)
}

/// A gpg-agent connection speaking just enough Assuan for our two commands.
pub struct GpgAgent {
    stream: Box<dyn Write>,
    reader: BufReader<Box<dyn Read>>,
}

/// Where Windows' emulated Assuan socket really listens. GnuPG writes the
/// socket "file" as the TCP port in ASCII, a newline, then a 16-byte nonce
/// that the client must send first to prove it may read the user's files.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_emulated_socket(data: &[u8]) -> Result<(u16, [u8; 16])> {
    let newline = data.iter().position(|&b| b == b'\n').context("malformed gpg-agent socket file")?;
    let port: u16 = std::str::from_utf8(&data[..newline])
        .ok()
        .and_then(|p| p.trim().parse().ok())
        .context("malformed gpg-agent socket file: no port")?;
    let nonce: [u8; 16] = data
        .get(newline + 1..newline + 17)
        .and_then(|n| n.try_into().ok())
        .context("malformed gpg-agent socket file: short nonce")?;
    Ok((port, nonce))
}

#[cfg(unix)]
fn open_agent(path: &str) -> Result<(Box<dyn Write>, Box<dyn Read>)> {
    let stream = std::os::unix::net::UnixStream::connect(path)
        .with_context(|| format!("no gpg-agent at {path}"))?;
    Ok((Box::new(stream.try_clone()?), Box::new(stream)))
}

#[cfg(windows)]
fn open_agent(path: &str) -> Result<(Box<dyn Write>, Box<dyn Read>)> {
    let data = fs::read(path).with_context(|| format!("no gpg-agent socket file at {path}"))?;
    let (port, nonce) = parse_emulated_socket(&data)?;
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .with_context(|| format!("no gpg-agent on 127.0.0.1:{port}"))?;
    stream.write_all(&nonce)?;
    Ok((Box::new(stream.try_clone()?), Box::new(stream)))
}

impl GpgAgent {
    pub fn connect() -> Result<Self> {
        gpgconf(&["--launch", "gpg-agent"])?;
        let path = gpgconf(&["--list-dirs", "agent-socket"])?;
        let (stream, reader) = open_agent(&path)?;
        let mut agent = Self { stream, reader: BufReader::new(reader) };
        agent.response()?;
        Ok(agent)
    }

    fn response(&mut self) -> Result<()> {
        let mut line = String::new();
        loop {
            line.clear();
            if self.reader.read_line(&mut line)? == 0 {
                bail!("gpg-agent closed the connection");
            }
            if line.starts_with("OK") {
                return Ok(());
            }
            if let Some(err) = line.strip_prefix("ERR ") {
                bail!("gpg-agent: {}", err.trim());
            }
        }
    }

    fn command(&mut self, line: &str) -> Result<()> {
        self.stream.write_all(line.as_bytes())?;
        self.stream.write_all(b"\n")?;
        self.response()
    }

    /// Caches the passphrase until cleared; gpg-agent ignores expiry for presets.
    pub fn preset(&mut self, keygrip: &str, passphrase: &str) -> Result<()> {
        let line = Zeroizing::new(format!("PRESET_PASSPHRASE {keygrip} -1 {}", hex(passphrase.as_bytes()).as_str()));
        self.command(&line)
    }

    pub fn clear(&mut self, keygrip: &str) -> Result<()> {
        self.command(&format!("CLEAR_PASSPHRASE --mode=normal {keygrip}"))
    }
}

/// Keygrips kleyknox has preset, so `lock` can clear them without the stick.
/// Holds nothing secret (see platform::state_dir).
fn state_path() -> Result<PathBuf> {
    Ok(platform::state_dir()?.join("gpg-loaded"))
}

pub fn loaded() -> Result<Vec<(String, Vec<String>)>> {
    let Ok(text) = fs::read_to_string(state_path()?) else { return Ok(Vec::new()) };
    Ok(text
        .lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            let name = parts.next()?.to_owned();
            Some((name, parts.map(str::to_owned).collect()))
        })
        .collect())
}

fn save_loaded(entries: &[(String, Vec<String>)]) -> Result<()> {
    let path = state_path()?;
    fs::create_dir_all(path.parent().unwrap())?;
    let text: String = entries.iter().map(|(n, g)| format!("{n} {}\n", g.join(" "))).collect();
    fs::write(path, text)?;
    Ok(())
}

pub fn mark_loaded(name: &str, keygrips: &[String]) -> Result<()> {
    let mut entries = loaded()?;
    entries.retain(|(n, _)| n != name);
    entries.push((name.to_owned(), keygrips.to_vec()));
    save_loaded(&entries)
}

/// Clears the cached passphrases of `name` (or of every loaded key) and
/// returns the names cleared.
pub fn lock(name: Option<&str>) -> Result<Vec<String>> {
    let entries = loaded()?;
    let (gone, kept): (Vec<_>, Vec<_>) =
        entries.into_iter().partition(|(n, _)| name.is_none_or(|t| t == n));
    if gone.is_empty() {
        return Ok(Vec::new());
    }
    let mut agent = GpgAgent::connect()?;
    for (n, grips) in &gone {
        for grip in grips {
            agent.clear(grip)?;
        }
        platform::cancel_expiry(n);
    }
    save_loaded(&kept)?;
    Ok(gone.into_iter().map(|(n, _)| n).collect())
}

fn hex(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for b in bytes {
        out.push_str(&format!("{b:02X}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_round_trip() {
        let b = Bundle {
            fingerprint: "ABCD".into(),
            keygrips: vec!["11".into(), "22".into()],
            passphrase: Zeroizing::new("s3cret".into()),
            secret_armor: Zeroizing::new("-----BEGIN PGP PRIVATE KEY BLOCK-----\n".into()),
        };
        let d = Bundle::decode(&b.encode()).unwrap();
        assert_eq!(d.fingerprint, "ABCD");
        assert_eq!(d.keygrips, ["11", "22"]);
        assert_eq!(d.passphrase.as_str(), "s3cret");
        assert!(d.secret_armor.starts_with("-----BEGIN"));
        assert!(Bundle::decode("not a bundle\n\narmor").is_err());
    }

    #[test]
    fn emulated_socket_file() {
        let mut data = b"49152\n".to_vec();
        data.extend(0u8..16);
        let (port, nonce) = parse_emulated_socket(&data).unwrap();
        assert_eq!(port, 49152);
        assert_eq!(nonce, core::array::from_fn::<u8, 16, _>(|i| i as u8));

        // A nonce may itself contain newlines: only the first one ends the port.
        let mut data = b"1234\n".to_vec();
        data.extend([b'\n'; 16]);
        assert_eq!(parse_emulated_socket(&data).unwrap().1, [b'\n'; 16]);

        assert!(parse_emulated_socket(b"1234\nshort").is_err());
        assert!(parse_emulated_socket(b"no newline").is_err());
        assert!(parse_emulated_socket(b"port\n0123456789abcdef").is_err());
    }

    #[test]
    fn hex_is_upper_case() {
        assert_eq!(hex(&[0x00, 0xab, 0x7f]).as_str(), "00AB7F");
    }
}
