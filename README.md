# keystick

SSH keys kept encrypted on a USB stick and decrypted only into `ssh-agent`, with an expiry.

- On the stick, `keystick/<name>.age` is the OpenSSH private key encrypted to a passphrase (age, scrypt), and `<name>.pub` is its public key.
- `keystick unlock` decrypts in memory and hands the key to the agent over its socket. No plaintext key is written to disk, and no other program sees it.
- The agent forgets the key after `--ttl` (default 2h), or on `keystick lock`.

## Use

```sh
keystick init /run/media/$USER/STICK      # once: creates the keystick/ directory
keystick new personale                    # new Ed25519 key, straight into the vault
keystick import lavoro ~/.ssh/id_ed25519  # or copy an existing Ed25519 key in
keystick list
keystick unlock personale --ttl 4h        # --confirm: ask on every use (needs SSH_ASKPASS)
keystick lock                             # drop every keystick key from the agent
```

It needs a running agent. With none, run `systemctl --user enable --now ssh-agent.socket` and set
`SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/ssh-agent.socket`. keystick falls back to that path on its own.

## Recovery without keystick

```sh
age -d /path/to/keystick/personale.age > key && chmod 600 key
```

## Limits

- Anyone holding the stick can guess the passphrase offline with no limit on attempts. Use a long one: at least 12 characters are enforced, and 5-6 random words are better.
- While a key is loaded, any process running as your user can use it through the agent. `--confirm` and a short `--ttl` limit that.
- Only Ed25519 keys are supported.
