mod agent;
mod vault;

use std::io::{BufRead, IsTerminal};
use std::path::PathBuf;

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ssh_key::private::KeypairData;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

use agent::Agent;

/// Comment prefix that marks agent identities loaded by keystick.
const COMMENT_PREFIX: &str = "keystick:";
const MIN_PASSPHRASE_CHARS: usize = 12;

#[derive(Parser)]
#[command(version, about = "SSH keys kept encrypted on a USB stick, decrypted only into ssh-agent")]
struct Cli {
    /// Vault directory (default: the keystick/ directory on the mounted stick)
    #[arg(long, global = true, env = "KEYSTICK_DIR")]
    dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a keystick/ directory on a mounted volume
    Init {
        /// Mount point of the stick
        mountpoint: PathBuf,
    },
    /// Generate a new Ed25519 key directly into the vault
    New {
        name: String,
        /// Replace an existing key with the same name
        #[arg(long)]
        force: bool,
    },
    /// Copy an existing Ed25519 private key into the vault
    Import {
        name: String,
        /// OpenSSH private key file (may itself be passphrase-protected)
        file: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Decrypt a key into ssh-agent
    Unlock {
        /// Key to load (default: the only key in the vault)
        name: Option<String>,
        /// How long the agent keeps it: 90s, 30m, 2h, 1d, or "none"
        #[arg(long, default_value = "2h")]
        ttl: String,
        /// Ask for confirmation on every use (needs SSH_ASKPASS in the agent's environment)
        #[arg(long)]
        confirm: bool,
    },
    /// Remove keystick keys from ssh-agent
    Lock {
        /// Key to remove (default: all keys loaded by keystick)
        name: Option<String>,
    },
    /// Show the keys in the vault and which are loaded
    List,
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("keystick: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init { mountpoint } => {
            let dir = mountpoint.join(vault::DIR_NAME);
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
            println!("vault ready at {}", dir.display());
        }
        Command::New { name, force } => {
            vault::check_name(&name)?;
            let dir = vault::locate(cli.dir)?;
            let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
            key.set_comment(format!("{COMMENT_PREFIX}{name}"));
            save(&dir, &name, &key, force)?;
        }
        Command::Import { name, file, force } => {
            vault::check_name(&name)?;
            let dir = vault::locate(cli.dir)?;
            let text = zeroize::Zeroizing::new(
                std::fs::read_to_string(&file)
                    .with_context(|| format!("cannot read {}", file.display()))?,
            );
            let mut key = PrivateKey::from_openssh(text.as_str())?;
            if key.is_encrypted() {
                let pass = read_passphrase(&format!("Current passphrase of {}: ", file.display()))?;
                key = key.decrypt(pass.expose_secret())?;
            }
            if key.algorithm() != Algorithm::Ed25519 {
                bail!("only Ed25519 keys are supported, this is {}", key.algorithm());
            }
            key.set_comment(format!("{COMMENT_PREFIX}{name}"));
            save(&dir, &name, &key, force)?;
            println!("the original {} is untouched; delete it once you trust the copy", file.display());
        }
        Command::Unlock { name, ttl, confirm } => {
            let dir = vault::locate(cli.dir)?;
            let name = match name {
                Some(n) => n,
                None => match vault::names(&dir)?.as_slice() {
                    [only] => only.clone(),
                    [] => bail!("the vault is empty; create a key with `keystick new <name>`"),
                    _ => bail!("several keys in the vault, name one (see `keystick list`)"),
                },
            };
            vault::check_name(&name)?;
            let lifetime = parse_ttl(&ttl)?;
            let mut agent = Agent::connect()?;

            let pass = read_passphrase(&format!("Passphrase for {name}: "))?;
            let text = vault::load(&dir, &name, pass)?;
            let key = PrivateKey::from_openssh(text.as_str())?;
            let KeypairData::Ed25519(pair) = key.key_data() else {
                bail!("{name} is not an Ed25519 key");
            };
            let seed = zeroize::Zeroizing::new(pair.private.to_bytes());
            agent.add_ed25519(
                &seed,
                &pair.public.0,
                &format!("{COMMENT_PREFIX}{name}"),
                lifetime,
                confirm,
            )?;

            let until = match lifetime {
                Some(s) => format!("for {}", ttl_label(s)),
                None => "until the agent stops".into(),
            };
            println!("{name} loaded into ssh-agent {until}{}", if confirm { ", confirm on use" } else { "" });
        }
        Command::Lock { name } => {
            let mut agent = Agent::connect()?;
            let target = name.map(|n| format!("{COMMENT_PREFIX}{n}"));
            let mut removed = 0;
            for id in agent.identities()? {
                let ours = match &target {
                    Some(t) => &id.comment == t,
                    None => id.comment.starts_with(COMMENT_PREFIX),
                };
                if ours {
                    agent.remove(&id.blob)?;
                    println!("removed {}", &id.comment[COMMENT_PREFIX.len()..]);
                    removed += 1;
                }
            }
            if removed == 0 {
                println!("no keystick keys were loaded");
            }
        }
        Command::List => {
            let dir = vault::locate(cli.dir)?;
            let loaded: Vec<String> = match Agent::connect() {
                Ok(mut a) => a.identities()?.into_iter().map(|i| i.comment).collect(),
                Err(_) => Vec::new(),
            };
            println!("vault: {}", dir.display());
            for name in vault::names(&dir)? {
                let mark = if loaded.contains(&format!("{COMMENT_PREFIX}{name}")) { "  [loaded]" } else { "" };
                println!("  {name}{mark}");
            }
        }
    }
    Ok(())
}

fn save(dir: &std::path::Path, name: &str, key: &PrivateKey, force: bool) -> Result<()> {
    let pass = read_new_passphrase()?;
    let private = key.to_openssh(LineEnding::LF)?;
    let public = key.public_key().to_openssh()?;
    vault::store(dir, name, &private, &format!("{public}\n"), pass, force)?;
    println!("stored {name} in {}", dir.display());
    println!("{public}");
    Ok(())
}

/// Prompts on the terminal; without one (scripts, tests) reads a line from stdin.
fn read_passphrase(prompt: &str) -> Result<SecretString> {
    let pass = if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt)?
    } else {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_owned()
    };
    if pass.is_empty() {
        bail!("empty passphrase");
    }
    Ok(SecretString::from(pass))
}

fn read_new_passphrase() -> Result<SecretString> {
    let first = read_passphrase("New passphrase: ")?;
    if first.expose_secret().chars().count() < MIN_PASSPHRASE_CHARS {
        bail!(
            "use at least {MIN_PASSPHRASE_CHARS} characters: anyone holding the stick can guess offline, forever"
        );
    }
    let second = read_passphrase("Repeat it: ")?;
    if first.expose_secret() != second.expose_secret() {
        bail!("the passphrases do not match");
    }
    Ok(first)
}

fn parse_ttl(s: &str) -> Result<Option<u32>> {
    if s == "none" {
        return Ok(None);
    }
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u32 = num.parse().with_context(|| format!("bad --ttl {s:?}"))?;
    let secs = match unit {
        "" | "s" => Some(n),
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3600),
        "d" => n.checked_mul(86400),
        _ => bail!("bad --ttl {s:?}: use s, m, h, d or none"),
    };
    match secs {
        Some(0) => bail!("--ttl must be positive (or none)"),
        Some(v) => Ok(Some(v)),
        None => bail!("--ttl {s:?} is too long"),
    }
}

fn ttl_label(secs: u32) -> String {
    match secs {
        s if s % 86400 == 0 => format!("{}d", s / 86400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}
