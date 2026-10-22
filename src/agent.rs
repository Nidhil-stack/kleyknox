//! Minimal ssh-agent client (draft-miller-ssh-agent): just the messages
//! kleyknox needs, so the decrypted key goes straight from our memory into
//! the agent's without touching disk or another process.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
const SSH_AGENT_CONSTRAIN_LIFETIME: u8 = 1;
const SSH_AGENT_CONSTRAIN_CONFIRM: u8 = 2;

pub struct Identity {
    pub blob: Vec<u8>,
    pub comment: String,
}

pub struct Agent {
    stream: UnixStream,
}

impl Agent {
    /// Connects to `$SSH_AUTH_SOCK`, falling back to the socket that
    /// `systemctl --user enable --now ssh-agent.socket` creates.
    pub fn connect() -> Result<Self> {
        let path = match std::env::var_os("SSH_AUTH_SOCK") {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => {
                let runtime = std::env::var_os("XDG_RUNTIME_DIR")
                    .context("neither SSH_AUTH_SOCK nor XDG_RUNTIME_DIR is set")?;
                PathBuf::from(runtime).join("ssh-agent.socket")
            }
        };
        let stream = UnixStream::connect(&path).with_context(|| {
            format!(
                "no ssh-agent at {} (start one: systemctl --user enable --now ssh-agent.socket)",
                path.display()
            )
        })?;
        Ok(Self { stream })
    }

    fn request(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        self.stream.write_all(&(msg.len() as u32).to_be_bytes())?;
        self.stream.write_all(msg)?;
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len)?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > 256 * 1024 {
            bail!("malformed reply from ssh-agent");
        }
        let mut reply = vec![0u8; len];
        self.stream.read_exact(&mut reply)?;
        Ok(reply)
    }

    fn expect_success(&mut self, msg: &[u8], what: &str) -> Result<()> {
        match self.request(msg)?.first() {
            Some(&SSH_AGENT_SUCCESS) => Ok(()),
            Some(&SSH_AGENT_FAILURE) => bail!("ssh-agent refused to {what}"),
            _ => bail!("unexpected reply from ssh-agent while trying to {what}"),
        }
    }

    /// Adds an Ed25519 key. `seed` and `public` are the raw 32-byte halves.
    pub fn add_ed25519(
        &mut self,
        seed: &[u8; 32],
        public: &[u8; 32],
        comment: &str,
        lifetime_secs: Option<u32>,
        confirm: bool,
    ) -> Result<()> {
        // The message carries the private key, so it is wiped once sent.
        let mut msg = Zeroizing::new(Vec::with_capacity(200));
        msg.push(SSH_AGENTC_ADD_ID_CONSTRAINED);
        put_string(&mut msg, b"ssh-ed25519");
        put_string(&mut msg, public);
        // OpenSSH stores the Ed25519 private key as seed || public.
        msg.extend_from_slice(&64u32.to_be_bytes());
        msg.extend_from_slice(seed);
        msg.extend_from_slice(public);
        put_string(&mut msg, comment.as_bytes());
        if let Some(secs) = lifetime_secs {
            msg.push(SSH_AGENT_CONSTRAIN_LIFETIME);
            msg.extend_from_slice(&secs.to_be_bytes());
        }
        if confirm {
            msg.push(SSH_AGENT_CONSTRAIN_CONFIRM);
        }
        self.expect_success(&msg, "add the key")
    }

    pub fn remove(&mut self, blob: &[u8]) -> Result<()> {
        let mut msg = vec![SSH_AGENTC_REMOVE_IDENTITY];
        put_string(&mut msg, blob);
        self.expect_success(&msg, "remove the key")
    }

    pub fn identities(&mut self) -> Result<Vec<Identity>> {
        let reply = self.request(&[SSH_AGENTC_REQUEST_IDENTITIES])?;
        let mut r = Reader(&reply);
        if r.byte()? != SSH_AGENT_IDENTITIES_ANSWER {
            bail!("unexpected reply from ssh-agent while listing keys");
        }
        let n = r.u32()?;
        let mut out = Vec::new();
        for _ in 0..n {
            let blob = r.string()?.to_vec();
            let comment = String::from_utf8_lossy(r.string()?).into_owned();
            out.push(Identity { blob, comment });
        }
        Ok(out)
    }
}

fn put_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            bail!("truncated reply from ssh-agent");
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}
