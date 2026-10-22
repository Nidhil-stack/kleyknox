//! What differs between Linux, macOS and Windows: where the per-session
//! state lives, how a key is locked again when its time is up, and how a
//! child process is detached from the terminal that started it.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use ssh_key::rand_core::{OsRng, RngCore};

/// Per-user state that holds nothing secret (which keys are unlocked, the
/// pending expiries). Linux: $XDG_RUNTIME_DIR, a tmpfs gone at logout.
/// Windows: %LOCALAPPDATA%. Elsewhere: the per-user temporary directory.
pub fn state_dir() -> Result<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from).context("LOCALAPPDATA is not set")?
    } else {
        match std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
            Some(dir) => PathBuf::from(dir),
            None => std::env::temp_dir(),
        }
    };
    let dir = base.join("kleyknox");
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    Ok(dir)
}

fn token_path(name: &str) -> Result<PathBuf> {
    Ok(state_dir()?.join(format!("expire-{name}")))
}

/// Locks `name` again after `secs`. On Linux a transient systemd timer does
/// it, so it survives the terminal and the session's other processes; where
/// systemd is missing (macOS, Windows, minimal Linux) a detached kleyknox
/// process waits and then runs `lock`.
pub fn schedule_expiry(name: &str, secs: u32) -> Result<()> {
    cancel_expiry(name);
    #[cfg(target_os = "linux")]
    if systemd_timer(name, secs).is_ok() {
        return Ok(());
    }
    detached_timer(name, secs)
}

/// Forgets a pending expiry, so a later unlock is not cut short by it.
pub fn cancel_expiry(name: &str) {
    #[cfg(target_os = "linux")]
    let _ = Command::new("systemctl")
        .args(["--user", "stop", &format!("{}.timer", timer_unit(name))])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    // A detached waiter checks its token before locking: removing it disarms the waiter.
    if let Ok(path) = token_path(name) {
        let _ = fs::remove_file(path);
    }
}

#[cfg(target_os = "linux")]
fn timer_unit(name: &str) -> String {
    format!("kleyknox-expire-{name}")
}

#[cfg(target_os = "linux")]
fn systemd_timer(name: &str, secs: u32) -> Result<()> {
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new("systemd-run");
    cmd.args(["--user", "--quiet", "--collect"])
        .arg(format!("--unit={}", timer_unit(name)))
        .arg(format!("--on-active={secs}s"))
        // systemd otherwise allows a timer to fire up to a minute late.
        .arg("--timer-property=AccuracySec=1s");
    // The lock must reach the same agents and the same state as this unlock.
    for var in ["GNUPGHOME", "SSH_AUTH_SOCK", "XDG_RUNTIME_DIR"] {
        if let Some(value) = std::env::var_os(var) {
            cmd.arg(format!("--setenv={var}={}", value.to_string_lossy()));
        }
    }
    let status = cmd
        .arg(exe)
        .args(["lock", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("cannot run systemd-run")?;
    if !status.success() {
        anyhow::bail!("systemd-run could not schedule the expiry");
    }
    Ok(())
}

fn detached_timer(name: &str, secs: u32) -> Result<()> {
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    fs::write(token_path(name)?, &token)?;

    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.args(["__expire", name, &secs.to_string(), &token])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    detach(&mut cmd);
    cmd.spawn().context("cannot start the expiry process")?;
    Ok(())
}

#[cfg(windows)]
fn detach(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
}

#[cfg(unix)]
fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // Its own process group: closing the terminal does not take it down.
    cmd.process_group(0);
}

/// The detached waiter (`kleyknox __expire`). Returns true when it is still
/// the current expiry for `name` once the time is up, so the caller locks.
pub fn wait_for_expiry(name: &str, secs: u32, token: &str) -> Result<bool> {
    std::thread::sleep(Duration::from_secs(secs.into()));
    let path = token_path(name)?;
    let current = fs::read_to_string(&path).unwrap_or_default();
    if current.trim() != token {
        return Ok(false);
    }
    let _ = fs::remove_file(path);
    Ok(true)
}
