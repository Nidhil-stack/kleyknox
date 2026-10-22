//! The `keystick/` directory on the USB stick: `<name>.age` holds the OpenSSH
//! private key encrypted to a passphrase (age + scrypt), `<name>.pub` its
//! public half. Either file can be used without keystick: `age -d name.age`.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

pub const DIR_NAME: &str = "keystick";

/// Finds the vault: an explicit path wins, otherwise every mounted removable
/// volume is searched for a `keystick/` directory.
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

pub fn names(dir: &Path) -> Result<Vec<String>> {
    let mut names: Vec<String> = fs::read_dir(dir)?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            name.strip_suffix(".age").map(str::to_owned)
        })
        .collect();
    names.sort();
    Ok(names)
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

pub fn store(
    dir: &Path,
    name: &str,
    private_openssh: &str,
    public_openssh: &str,
    passphrase: SecretString,
    force: bool,
) -> Result<()> {
    let age_path = dir.join(format!("{name}.age"));
    if age_path.exists() && !force {
        bail!("{} already exists (use --force to replace it)", age_path.display());
    }

    let mut ciphertext = Vec::new();
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);
    let mut writer = encryptor.wrap_output(&mut ciphertext)?;
    writer.write_all(private_openssh.as_bytes())?;
    writer.finish()?;

    write_atomic(&age_path, &ciphertext)?;
    write_atomic(&dir.join(format!("{name}.pub")), public_openssh.as_bytes())?;
    Ok(())
}

pub fn load(dir: &Path, name: &str, passphrase: SecretString) -> Result<Zeroizing<String>> {
    let age_path = dir.join(format!("{name}.age"));
    let file = fs::File::open(&age_path)
        .with_context(|| format!("no key named {name} in {}", dir.display()))?;

    let decryptor = age::Decryptor::new(file)?;
    if !decryptor.is_scrypt() {
        bail!("{} is not passphrase-encrypted", age_path.display());
    }
    let identity = age::scrypt::Identity::new(passphrase);
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
