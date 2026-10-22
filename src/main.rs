mod agent;
mod gpg;
mod vault;

use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ssh_key::private::KeypairData;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use zeroize::Zeroizing;

use agent::Agent;
use vault::Kind;

/// Comment prefix that marks agent identities loaded by keystick.
const COMMENT_PREFIX: &str = "keystick:";
const MIN_PASSPHRASE_CHARS: usize = 12;

#[derive(Parser)]
#[command(version, about = "SSH and GPG keys kept encrypted on a USB stick, unlocked with one passphrase")]
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
    /// Generate a new Ed25519 SSH key directly into the vault
    New {
        name: String,
        /// Replace an existing entry with the same name
        #[arg(long)]
        force: bool,
    },
    /// Copy an existing Ed25519 SSH private key into the vault
    Import {
        name: String,
        /// OpenSSH private key file (may itself be passphrase-protected)
        file: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Generate a new GPG key (Ed25519 + Cv25519) and put it in the vault
    GpgNew {
        name: String,
        /// User ID, e.g. "Nome Cognome <nome@example.org>"
        uid: String,
        #[arg(long)]
        force: bool,
    },
    /// Put a GPG secret key from your keyring in the vault
    GpgImport {
        name: String,
        /// Fingerprint, key ID or email of the key
        key: String,
        #[arg(long)]
        force: bool,
    },
    /// Unlock SSH and GPG keys with the vault passphrase
    Unlock {
        /// Entry to unlock (default: everything in the vault)
        name: Option<String>,
        /// How long keys stay usable: 90s, 30m, 2h, 1d, or "none"
        #[arg(long, default_value = "2h")]
        ttl: String,
        /// SSH: ask for confirmation on every use (needs SSH_ASKPASS in the agent's environment)
        #[arg(long)]
        confirm: bool,
    },
    /// Lock keys again: remove SSH keys from ssh-agent, forget GPG passphrases
    Lock {
        /// Entry to lock (default: everything keystick unlocked)
        name: Option<String>,
    },
    /// Show the vault's entries and which are unlocked
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
            save_ssh(&dir, &name, &key, force)?;
        }
        Command::Import { name, file, force } => {
            vault::check_name(&name)?;
            let dir = vault::locate(cli.dir)?;
            let text = Zeroizing::new(
                std::fs::read_to_string(&file)
                    .with_context(|| format!("cannot read {}", file.display()))?,
            );
            let mut key = PrivateKey::from_openssh(text.as_str())?;
            if key.is_encrypted() {
                let pass = read_passphrase(&format!("Current passphrase of {}: ", file.display()), false)?;
                key = key.decrypt(pass.as_bytes())?;
            }
            if key.algorithm() != Algorithm::Ed25519 {
                bail!("only Ed25519 keys are supported, this is {}", key.algorithm());
            }
            key.set_comment(format!("{COMMENT_PREFIX}{name}"));
            save_ssh(&dir, &name, &key, force)?;
            println!("the original {} is untouched; delete it once you trust the copy", file.display());
        }
        Command::GpgNew { name, uid, force } => {
            vault::check_name(&name)?;
            let dir = vault::locate(cli.dir)?;
            refuse_overwrite(&dir, Kind::Gpg, &name, force)?;
            // Asked first, so a typo here does not leave an orphan key in the keyring.
            let pass = read_new_passphrase()?;
            let bundle = gpg::generate(&uid)?;
            save_gpg(&dir, &name, &bundle, pass, force)?;
            println!("revocation certificate: openpgp-revocs.d/{}.rev in your GnuPG home", bundle.fingerprint);
        }
        Command::GpgImport { name, key, force } => {
            vault::check_name(&name)?;
            let dir = vault::locate(cli.dir)?;
            refuse_overwrite(&dir, Kind::Gpg, &name, force)?;
            let current = read_passphrase("Current GPG passphrase of the key (empty if none): ", true)?;
            let bundle = gpg::existing(&key, current).context("wrong GPG passphrase, or the key cannot be exported")?;
            if bundle.passphrase.is_empty() {
                eprintln!("warning: this key has no GPG passphrase, so it sits unprotected in the keyring of every PC you unlock it on");
            }
            let pass = read_new_passphrase()?;
            save_gpg(&dir, &name, &bundle, pass, force)?;
        }
        Command::Unlock { name, ttl, confirm } => unlock(cli.dir, name, &ttl, confirm)?,
        Command::Lock { name } => lock(name)?,
        Command::List => {
            let dir = vault::locate(cli.dir)?;
            let ssh_loaded: Vec<String> = match Agent::connect() {
                Ok(mut a) => a.identities()?.into_iter().map(|i| i.comment).collect(),
                Err(_) => Vec::new(),
            };
            let gpg_loaded: Vec<String> = gpg::loaded()?.into_iter().map(|(n, _)| n).collect();
            println!("vault: {}", dir.display());
            for item in vault::items(&dir)? {
                let unlocked = match item.kind {
                    Kind::Ssh => ssh_loaded.contains(&format!("{COMMENT_PREFIX}{}", item.name)),
                    Kind::Gpg => gpg_loaded.contains(&item.name),
                };
                let mark = if unlocked { "  [unlocked]" } else { "" };
                println!("  {}  {}{mark}", item.kind.label(), item.name);
            }
        }
    }
    Ok(())
}

fn unlock(dir: Option<PathBuf>, name: Option<String>, ttl: &str, confirm: bool) -> Result<()> {
    let dir = vault::locate(dir)?;
    let lifetime = parse_ttl(ttl)?;
    let mut items = vault::items(&dir)?;
    if let Some(n) = &name {
        vault::check_name(n)?;
        items.retain(|i| &i.name == n);
        if items.is_empty() {
            bail!("no entry named {n} (see `keystick list`)");
        }
    }
    if items.is_empty() {
        bail!("the vault is empty; add a key with `keystick new` or `keystick gpg-new`");
    }

    let pass = read_passphrase("Keystick passphrase: ", false)?;
    let until = match lifetime {
        Some(s) => format!("for {}", ttl_label(s)),
        None => "until `keystick lock`".into(),
    };
    let mut ssh_agent = None;
    let mut failed = 0;
    for item in &items {
        let result = match item.kind {
            Kind::Ssh => unlock_ssh(&dir, &item.name, &pass, &mut ssh_agent, lifetime, confirm),
            Kind::Gpg => unlock_gpg(&dir, &item.name, &pass, lifetime),
        };
        match result {
            Ok(()) => println!("{} {} unlocked {until}", item.kind.label(), item.name),
            Err(e) => {
                eprintln!("{} {}: {e:#}", item.kind.label(), item.name);
                failed += 1;
            }
        }
    }
    if failed > 0 {
        bail!("{failed} of {} entries were not unlocked", items.len());
    }
    Ok(())
}

fn unlock_ssh(
    dir: &Path,
    name: &str,
    pass: &str,
    agent: &mut Option<Agent>,
    lifetime: Option<u32>,
    confirm: bool,
) -> Result<()> {
    let text = vault::load(dir, &Kind::Ssh.stem(name), secret(pass))?;
    let key = PrivateKey::from_openssh(text.as_str())?;
    let KeypairData::Ed25519(pair) = key.key_data() else {
        bail!("not an Ed25519 key");
    };
    let seed = Zeroizing::new(pair.private.to_bytes());
    let agent = match agent {
        Some(a) => a,
        None => agent.insert(Agent::connect()?),
    };
    agent.add_ed25519(&seed, &pair.public.0, &format!("{COMMENT_PREFIX}{name}"), lifetime, confirm)
}

fn unlock_gpg(dir: &Path, name: &str, pass: &str, lifetime: Option<u32>) -> Result<()> {
    let text = vault::load(dir, &Kind::Gpg.stem(name), secret(pass))?;
    let bundle = gpg::Bundle::decode(&text)?;
    if gpg::ensure_imported(&bundle)? {
        println!("gpg {name}: secret key {} imported into this keyring (still passphrase-protected)", bundle.fingerprint);
    }
    if !bundle.passphrase.is_empty() {
        if gpg::ensure_preset_allowed()? {
            println!("gpg: enabled allow-preset-passphrase in gpg-agent.conf");
        }
        let mut agent = gpg::GpgAgent::connect()?;
        for grip in &bundle.keygrips {
            agent.preset(grip, &bundle.passphrase)?;
        }
    }
    gpg::mark_loaded(name, &bundle.keygrips)?;
    if let Some(secs) = lifetime {
        if let Err(e) = gpg::schedule_expiry(name, secs) {
            eprintln!("gpg {name}: will NOT lock itself ({e:#}); run `keystick lock` when done");
        }
    }
    Ok(())
}

fn lock(name: Option<String>) -> Result<()> {
    if let Some(n) = &name {
        vault::check_name(n)?;
    }
    // GPG first: the expiry timer runs this without an ssh-agent in its environment.
    let mut done = 0;
    for n in gpg::lock(name.as_deref())? {
        println!("locked gpg {n}");
        done += 1;
    }

    let target = name.map(|n| format!("{COMMENT_PREFIX}{n}"));
    match Agent::connect() {
        Ok(mut agent) => {
            for id in agent.identities()? {
                let ours = match &target {
                    Some(t) => &id.comment == t,
                    None => id.comment.starts_with(COMMENT_PREFIX),
                };
                if ours {
                    agent.remove(&id.blob)?;
                    println!("locked ssh {}", &id.comment[COMMENT_PREFIX.len()..]);
                    done += 1;
                }
            }
        }
        Err(e) if done == 0 => return Err(e),
        Err(_) => {}
    }
    if done == 0 {
        println!("nothing was unlocked");
    }
    Ok(())
}

fn refuse_overwrite(dir: &Path, kind: Kind, name: &str, force: bool) -> Result<()> {
    let path = dir.join(format!("{}.age", kind.stem(name)));
    if path.exists() && !force {
        bail!("{} already exists (use --force to replace it)", path.display());
    }
    Ok(())
}

fn save_ssh(dir: &Path, name: &str, key: &PrivateKey, force: bool) -> Result<()> {
    refuse_overwrite(dir, Kind::Ssh, name, force)?;
    let pass = read_new_passphrase()?;
    let private = key.to_openssh(LineEnding::LF)?;
    let public = key.public_key().to_openssh()?;
    vault::store(
        dir,
        &Kind::Ssh.stem(name),
        private.as_bytes(),
        (&format!("{name}.pub"), &format!("{public}\n")),
        secret(&pass),
        force,
    )?;
    println!("stored ssh {name} in {}", dir.display());
    println!("{public}");
    Ok(())
}

fn save_gpg(dir: &Path, name: &str, bundle: &gpg::Bundle, pass: Zeroizing<String>, force: bool) -> Result<()> {
    let public = gpg::public_armor(&bundle.fingerprint)?;
    vault::store(
        dir,
        &Kind::Gpg.stem(name),
        bundle.encode().as_bytes(),
        (&format!("{name}.asc"), &public),
        secret(&pass),
        force,
    )?;
    println!("stored gpg {name} ({}) in {}", bundle.fingerprint, dir.display());
    Ok(())
}

fn secret(pass: &str) -> SecretString {
    SecretString::from(pass.to_owned())
}

/// Prompts on the terminal; without one (scripts, tests) reads a line from stdin.
fn read_passphrase(prompt: &str, allow_empty: bool) -> Result<Zeroizing<String>> {
    let pass = Zeroizing::new(if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt)?
    } else {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
        zeroize::Zeroize::zeroize(&mut line);
        trimmed
    });
    if pass.is_empty() && !allow_empty {
        bail!("empty passphrase");
    }
    Ok(pass)
}

fn read_new_passphrase() -> Result<Zeroizing<String>> {
    let first = read_passphrase("New keystick passphrase (use the same for every entry): ", false)?;
    if first.chars().count() < MIN_PASSPHRASE_CHARS {
        bail!(
            "use at least {MIN_PASSPHRASE_CHARS} characters: anyone holding the stick can guess offline, forever"
        );
    }
    let second = read_passphrase("Repeat it: ", false)?;
    if first != second {
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
