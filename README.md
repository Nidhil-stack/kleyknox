# keystick

SSH and GPG keys kept encrypted on a USB stick, all unlocked with one passphrase, for a limited time.

On the stick, in `keystick/`, every secret is encrypted to the same passphrase (age, scrypt):

| File | Contents |
| --- | --- |
| `<name>.age` + `<name>.pub` | OpenSSH Ed25519 private key + public key |
| `<name>.gpg.age` + `<name>.asc` | GPG secret key export + the passphrase protecting it, and the public key |

`keystick unlock` asks the passphrase once and then does two things:

- **SSH**: decrypts the key in memory and hands it to `ssh-agent` over its socket, with a lifetime. No plaintext key touches the disk.
- **GPG**: imports the secret key when this machine lacks it (it stays protected by its GPG passphrase, which only the stick knows), then presets that passphrase in `gpg-agent`. gpg-agent has no expiry for presets, so keystick schedules `keystick lock <name>` with a transient systemd user timer.

## Use

```sh
keystick init /run/media/$USER/STICK         # once: creates the keystick/ directory
keystick new personale                       # new SSH key, straight into the vault
keystick import lavoro ~/.ssh/id_ed25519     # or copy an existing Ed25519 SSH key in
keystick gpg-new mail "Nome <nome@example.org>"   # new GPG key (Ed25519 + Cv25519)
keystick gpg-import vecchia nome@example.org      # or an existing GPG key from the keyring
keystick list
keystick unlock --ttl 4h                     # everything; or `unlock <name>`
keystick lock                                # everything keystick unlocked; or `lock <name>`
```

Use the same passphrase for every entry: `unlock` tries it on all of them.

SSH needs a running agent: `systemctl --user enable --now ssh-agent.socket` and
`SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/ssh-agent.socket`. keystick falls back to that path on its own.
For GPG, the first unlock adds `allow-preset-passphrase` to `gpg-agent.conf`.

## Recovery without keystick

```sh
age -d personale.age > key && chmod 600 key   # SSH key
age -d mail.gpg.age                           # header with the GPG passphrase, then the key to `gpg --import`
```

## Limits

- Anyone holding the stick can guess the passphrase offline with no limit on attempts. Use a long one: at least 12 characters are enforced, and 5-6 random words are better.
- While keys are unlocked, any process running as your user can use them. Keep `--ttl` short, and use `--confirm` for SSH.
- GPG keys stay in the keyring of every PC where you unlock them, protected by a random passphrase that only the stick knows. Delete them with `gpg --delete-secret-keys` on PCs you do not own.
- Only Ed25519 keys are supported for SSH.
