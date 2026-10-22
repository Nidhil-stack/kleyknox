//! The `kleyknox/` directory on the USB stick, every secret encrypted to the
//! same passphrase (age + scrypt) and readable without kleyknox (`age -d`):
//! - `<name>.age`: an OpenSSH private key, with `<name>.pub` beside it
//! - `<name>.gpg.age`: a GPG entry (see gpg.rs), with `<name>.asc` beside it

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

pub const DIR_NAME: &str = "kleyknox";

/// scrypt cost (log2 N) for new entries: about 1 GiB and a second or two to
/// open. Fixed rather than calibrated to this PC, so a vault written on a fast
/// machine still opens on a slow one.
const WORK_FACTOR: u8 = 20;
/// Highest cost accepted when opening, so a tampered file cannot demand hours.
pub const MAX_WORK_FACTOR: u8 = 22;

/// Finds the vault: an explicit path wins, otherwise every mounted removable
/// volume is searched for a `kleyknox/` directory.
pub fn locate(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = explicit {
        if !dir.is_dir() {
            bail!("{} is not a directory", dir.display());
        }
        return Ok(dir);
    }

    let user = std::env::var("USER").unwrap_or_default();
    let roots = [
        PathBuf::from("/run/media").join(&user),
        PathBuf::from("/media").join(&user),
        PathBuf::from("/media"),
        PathBuf::from("/mnt"),
    ];
    let mut found = Vec::new();
    for root in roots {
        let Ok(entries) = fs::read_dir(&root) else { continue };
        for entry in entries.flatten() {
            let candidate = entry.path().join(DIR_NAME);
            if candidate.is_dir() {
                found.push(candidate);
            }
        }
    }

    match found.len() {
        0 => bail!(
            "no mounted volume has a {DIR_NAME}/ directory; plug in the stick or pass --dir"
        ),
        1 => Ok(found.remove(0)),
        _ => {
            let list: Vec<_> = found.iter().map(|p| p.display().to_string()).collect();
            bail!("several vaults found, pick one with --dir:\n  {}", list.join("\n  "))
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ssh,
    Gpg,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Ssh => "ssh",
            Kind::Gpg => "gpg",
        }
    }

    /// File name without `.age`; names never contain dots, so this is unambiguous.
    pub fn stem(self, name: &str) -> String {
        match self {
            Kind::Ssh => name.to_owned(),
            Kind::Gpg => format!("{name}.gpg"),
        }
    }
}

pub struct Item {
    pub name: String,
    pub kind: Kind,
}

pub fn items(dir: &Path) -> Result<Vec<Item>> {
    let mut items: Vec<Item> = fs::read_dir(dir)?
        .flatten()
        .filter_map(|e| {
            let file = e.file_name().into_string().ok()?;
            let stem = file.strip_suffix(".age")?;
            Some(match stem.strip_suffix(".gpg") {
                Some(name) => Item { name: name.to_owned(), kind: Kind::Gpg },
                None => Item { name: stem.to_owned(), kind: Kind::Ssh },
            })
        })
        .collect();
    items.sort_by(|a, b| (&a.name, a.kind.label()).cmp(&(&b.name, b.kind.label())));
    Ok(items)
}

pub fn check_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !ok {
        bail!("key names use only letters, digits, - and _ (max 64)");
    }
    Ok(())
}

/// Encrypts `secret` to `<stem>.age` and writes `public` (a non-secret
/// companion such as a .pub or .asc file) next to it.
pub fn store(
    dir: &Path,
    stem: &str,
    secret: &[u8],
    public: (&str, &str),
    passphrase: SecretString,
    force: bool,
) -> Result<()> {
    let age_path = dir.join(format!("{stem}.age"));
    if age_path.exists() && !force {
        bail!("{} already exists (use --force to replace it)", age_path.display());
    }

    let mut ciphertext = Vec::new();
    let mut recipient = age::scrypt::Recipient::new(passphrase);
    recipient.set_work_factor(WORK_FACTOR);
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?;
    let mut writer = encryptor.wrap_output(&mut ciphertext)?;
    writer.write_all(secret)?;
    writer.finish()?;

    write_atomic(&age_path, &ciphertext)?;
    write_atomic(&dir.join(public.0), public.1.as_bytes())?;
    Ok(())
}

pub fn load(dir: &Path, stem: &str, passphrase: SecretString) -> Result<Zeroizing<String>> {
    let age_path = dir.join(format!("{stem}.age"));
    let file = fs::File::open(&age_path)
        .with_context(|| format!("{} not found", age_path.display()))?;

    let decryptor = age::Decryptor::new(file)?;
    if !decryptor.is_scrypt() {
        bail!("{} is not passphrase-encrypted", age_path.display());
    }
    let mut identity = age::scrypt::Identity::new(passphrase);
    identity.set_max_work_factor(MAX_WORK_FACTOR);
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::DecryptionFailed | age::DecryptError::NoMatchingKeys => {
                anyhow::anyhow!("wrong passphrase")
            }
            other => other.into(),
        })?;

    let mut plain = Zeroizing::new(String::new());
    reader.read_to_string(&mut plain)?;
    Ok(plain)
}

/// Writes through a temporary file and renames it, so pulling the stick out
/// mid-write leaves either the old file or the new one, never half of one.
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}
