# Shamir shares with systemd encrypted credentials

The default `config` storage provider preserves `unseal_tokens`, `--tokens`,
and environment configuration. The `systemd` provider reads one Shamir share per
named credential from `$CREDENTIALS_DIRECTORY`. It never writes plaintext shares
or executes a decryption subprocess. systemd decrypts credentials before starting
the service and controls access to their runtime files.

This changes how Shamir shares are stored, not Vault's seal mechanism. It works
with existing Shamir-sealed clusters. It does not initialize Vault, generate
shares, or change your threshold. Keep the existing distribution of shares across
unsealers; do not put a threshold's worth of shares on one host merely because
they are encrypted.

## Requirements and TPM policy

Use Linux with systemd 250 or newer, including `systemd-creds` and support for
`LoadCredentialEncrypted=`. The daemon itself does not need TPM device access;
the system service manager decrypts the credential before sandboxing the daemon.

Provision credentials **on the host that will run the service**.
`systemd-creds encrypt --with-key=auto` uses the TPM2 when available and usable,
and the host secret where available. On a host without a usable TPM, it can use
the host secret alone. A credential already bound to a TPM cannot fall back to
host-only decryption if that TPM later becomes unavailable.

To require both TPM2 and the host secret, replace `--with-key=auto` below with
`--with-key=host+tpm2`; provisioning will fail if unavailable. Use
`systemd-creds has-tpm2` to inspect support. PCR binding follows the installed
systemd defaults; inspect `man systemd-creds` and choose an explicit
`--tpm2-pcrs=` policy if needed for your boot/update process. Do not disable PCR
binding just to work around an unexplained decryption failure.

## Provision an existing share

In an interactive root Bash shell, run the following for each share assigned to
this unsealer. The hidden prompt avoids putting the share in shell history or a
process argument. Do not enable shell tracing (`set -x`).

```bash
install -d -m 0700 /etc/credstore.encrypted
umask 077
read -r -s -p 'Shamir share: ' share; printf '\n'
printf '%s' "$share" | systemd-creds encrypt \
  --with-key=auto --name=vault-unseal-share-1 \
  - /etc/credstore.encrypted/vault-unseal-share-1.cred
unset share
```

Repeat with `vault-unseal-share-2` if this host is assigned two shares. Each
credential contains the raw base64 or hexadecimal share, with an optional final
newline, not YAML, JSON, or a list. The encrypted credential's `--name` must match
the name in `LoadCredentialEncrypted=`.

## Configure the daemon and service

Remove `unseal_tokens` from `/etc/vault-unseal.yaml`, and remove tokens supplied
through CLI flags or environment variables. Retain your existing nodes, TLS,
notifications, and other configuration. Add:

```yaml
storage:
  provider: systemd
  credentials:
    - vault-unseal-share-1
    - vault-unseal-share-2
```

Alternatively use `--storage.provider=systemd` and
`--storage.credentials=vault-unseal-share-1,vault-unseal-share-2`.
Credentials are selected explicitly and read in the configured order. The
provider refuses mixed inline tokens and systemd credentials, duplicate or
invalid names, missing files, symlinks, empty or multiline values, and files
larger than 16 KiB. It validates credentials at startup and loads them again for
each unseal attempt. It does not include credential contents in storage errors.

Install the example drop-in:

```bash
install -d -m 0755 /etc/systemd/system/vault-unseal.service.d
install -m 0644 scripts/systemd-credentials.conf \
  /etc/systemd/system/vault-unseal.service.d/credentials.conf
systemctl daemon-reload
systemctl restart vault-unseal.service
systemctl status vault-unseal.service
```

Remove the second credential from both places if this host is assigned one share.
The example is a drop-in for the existing packaged system service, not a complete
standalone unit. Keep the configuration permissions required by the existing
application (for example, `0600`).

## Rotation, migration, and recovery

After replacing an encrypted credential, restart the service: systemd loads a
snapshot at service activation. Editing the YAML alone does not refresh that
snapshot. Provision and verify credentials before removing old plaintext copies;
after a successful migration, remove those copies from config, environment files,
and your configuration-management source as appropriate. Existing backups may
still contain plaintext.

Keep an offline recovery quorum independent of the host and TPM. TPM reset,
motherboard replacement, loss of the host secret, or PCR policy changes can make
the encrypted copy unusable. Restore service by provisioning shares from that
quorum on the replacement host. Encryption at rest does not protect shares from
a compromised running unsealer or a privileged attacker who can read its memory
or runtime credentials. Host-secret-only protection is also weaker against disk
theft when that secret is on the same unencrypted disk.

References: [systemd credentials](https://systemd.io/CREDENTIALS/),
[systemd-creds](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html),
[systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
