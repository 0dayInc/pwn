# YubiKey-backed vaults and authentication

See [YubiKey device operations](YubiKey.md) for native HID/PC/SC operations,
provisioning safeguards and the firmware boundary. No `ykman` process is used.

## Encryption model

This is **hardware-derived key encryption**, not bulk encryption inside the
YubiKey. An already provisioned OTP HMAC-SHA1 slot answers a fresh random
32-byte challenge. Ruby derives a 32-byte encryption key using HKDF-SHA256 with
a fresh 16-byte salt and a domain-specific context, then uses AES-256-GCM with
a fresh nonce and a full 16-byte tag. The HMAC response and derived key exist
transiently in the Ruby process; the slot secret is not exported. Ruby does not
promise zeroization of copied strings.

The versioned `PWN-YUBIKEY-VAULT:1` envelope authenticates its metadata as AAD.
The public challenge, salt, slot and optional serial are stored with ciphertext,
not in a secret sidecar. Executable paths and timeout overrides are supplied
by the caller, never loaded from ciphertext. PINs, OTP codes and serial numbers
are not encryption keys. HMAC-SHA1 is used as the device PRF, not as an
unauthenticated document hash; it provides at most the slot/response security,
not 256 bits of entropy merely because AES-256 is used.

Existing Base64 AES-256-CBC files and software loot remain readable. New
hardware protection is opt-in; no existing configuration is migrated merely by
loading PWN. A hardware envelope never falls back to a software master key,
passphrase or unauthenticated plaintext when a device is missing or a tag fails.
Do not combine a software key/IV or passphrase/keyring with hardware selection.

## Use an existing HMAC slot

Use a key model supporting OTP HMAC challenge-response. FIDO-only Security Keys
do not support this vault backend. Set up the slot explicitly using the device
management interface; prefer its physical-touch policy. PWN never provisions,
replaces, unlocks by guessing, or resets a slot in order to open a vault.

```ruby
# The named file must already contain the plaintext you intend to encrypt.
PWN::Plugins::Vault.create(file: '/path/to/private.yaml', yubikey: { slot: 2 })

# With multiple devices, explicitly select the intended device serial.
# Serial is a placeholder; replace locally, never paste secrets into a transcript.
selector = { slot: 2, serial: '12345678' }
PWN::Plugins::Vault.encrypt(file: '/path/to/another.yaml', yubikey: selector)

# Read-only: decrypted data exists in memory, not an intermediate file.
config = PWN::Plugins::Vault.dump(file: '/path/to/private.yaml'); nil

# Mutate YAML in memory and atomically publish ciphertext, preserving the backend.
PWN::Plugins::Vault.update(file: '/path/to/private.yaml') do |document|
  document[:setting] = 'replacement'
end
```

`yubikey` is a Hash accepting `slot` (integer 1 or 2; default 2), optional
exact decimal `serial`, optional `reader` or `device_path`, and bounded
`timeout` seconds. An executable path such as `ykman` is rejected. The
envelope stores slot and serial only; it never stores a backend path.
`dump`, `decrypt`, `open_credentials` and hardware loot retrieval otherwise use
the slot/serial stored in their envelope. Selecting another serial permits an
explicitly provisioned recovery key with the same slot secret; the authentication
tag still has to verify. A different slot requires explicit rewrapping.

`encrypt_data` / `decrypt_data` are in-memory String APIs, including arbitrary
binary data and empty plaintext. `seal_credentials` / `open_credentials` work
on JSON-compatible credential values. Neither API opens the live configuration
or writes keys. `file_encrypted?` / `hardware_encrypted?` inspect format only;
they do not prove the device is present or that a ciphertext authenticates.

`decrypt(file:)` explicitly replaces ciphertext with plaintext. Use `dump`
instead when plaintext-on-disk is unnecessary. `edit` explicitly gives a private
0600 temporary copy to the chosen editor under `~/.pwn/workspaces/runtime`, then
removes its private working directory. The original stays encrypted until a
successful re-encryption and atomic replacement. Editors are trusted programs:
their external backups, OS swap, crash dumps and an abruptly killed process are
not a secure-erasure guarantee. The curses `/vault edit` editor works in memory
and writes only ciphertext. Built-in file writers share its parent-directory
advisory lock across the final baseline check and atomic rename. A stale edit
raises rather than overwriting a newer publication. This is not a filesystem
compare-and-swap guarantee against external writers that ignore the lock.

## Conversion and recovery

Before converting a legacy vault, retain its verified encrypted backup and
legacy decryptor somewhere secure. Conversion is explicit:

```ruby
PWN::Plugins::Vault.refresh_encryption_secrets(
  file: '/path/to/legacy.yaml',
  key: legacy_key, iv: legacy_iv,
  new_yubikey: { slot: 2 }
)
```

No temporary plaintext is published during conversion. On an existing hardware
vault, `refresh_encryption_secrets(file:)` rewraps with fresh challenge/salt/nonce;
it does **not** change the device secret. Supply `new_yubikey:` to move to another
already provisioned slot/device while the old one is available. An explicit
`new_yubikey:` must be a valid selector Hash; values such as `false` are rejected
before opening the source vault, not treated as a request for software rotation.
Hardware access or encryption failure leaves the original ciphertext intact. Old software
sidecars and backups are not silently deleted; retire them deliberately after
verifying recovery.

Losing or reprogramming the only usable slot loses access. A ciphertext backup
alone is not an independent recovery key. Establish and test an appropriate
recovery device/secret before relying on hardware-only storage. Removing a
YubiKey does not erase an already unlocked `PWN::Env` or revoke remote tokens;
the application retains its in-memory configuration until exit/refresh.

## Integration coverage

| Entry point | Hardware behavior |
|---|---|
| `Vault.create/encrypt/decrypt/dump/edit/refresh_encryption_secrets` | Explicit creation/conversion, automatic envelope detection on read, backend-preserving edits |
| `Vault.seal_credentials/open_credentials` | Authenticated in-memory hardware envelopes alongside existing passphrase/keyring formats |
| `Vault.store/fetch/offer/ingest/expand/redact` | Optional hardware-protected engagement records; metadata-only `query` does not touch hardware |
| `BasicAuth.encode(host:)` | Resolves matching protected loot through Vault, not a separate crypto implementation |
| `Redaction.capture` and `Recon` loot ingestion | Explicit hardware selector for new captures; locked-store failure never creates a software-key fallback |
| `Config.default_env/refresh_env` | Explicit hardware creation; hardware loading without a legacy decryptor sidecar |
| `Migrate.vault_drift/backfill_vault` | Read/merge through Vault, preserving hardware format and user settings |
| `pwn-vault`, `/vault edit`, `/model`, `/system-role`, mesh settings | Backend-aware encrypted persistence; no duplicate CBC-only write path |
| OpenAI, Anthropic, Grok and Google Workspace OAuth persistence | In-memory configuration merge, ciphertext-only atomic save; hardware unavailability reports persistence failure |
| `AuthenticationHelper.mfa` and supported WWW login methods | Explicit exact-account OATH code lookup, separate from ordinary manual MFA |

Hardware-protected loot reads may require a touch, including explicit expansion
and secret-value redaction. Do not enable it for unattended workflows expecting
unbounded automatic access. Background metadata discovery and help do not unlock
hardware. Existing unrelated records are not implicitly re-encrypted. Missing
loot stores are empty; an existing unreadable store, malformed JSON, or invalid
record/envelope shape raises `IOError` on reads and writes, including metadata
queries. PWN does not infer a software backend from corrupt records, generate a
replacement master key, or overwrite the damaged store. Restore a verified backup
before retrying.

## Explicit OATH authentication

Select an exact account and authorize its effects explicitly:

```ruby
code = PWN::Plugins::AuthenticationHelper.mfa(
  yubikey: { account: 'Example:alice', serial: '12345678', confirm: true }
); nil
```

The same `yubikey:` Hash is accepted by GitHub, Synack, Twitter, BugCrowd,
CoinbasePro and AppCobaltIO login methods. Lookup occurs at the authenticator
form, not during option validation. Missing/nonliteral consent is rejected before
password prompts or navigation. Device errors do not fall back to manual MFA;
explicit manual tokens cannot be combined with the hardware selector. PayPal's
current SMS-only adapter rejects OATH even with consent, and GitHub's SMS-only
challenge does not accept an authenticator code.

For `pwn_web_cache_deception`, add `--yubikey-account='Example:alice'`, optionally
`--yubikey-serial=12345678`, and the required `--yubikey-confirm` to the normal
arguments for a compatible login module. The flag authorizes native OATH
authentication and HOTP counter advancement. It does not authorize deleting or
repairing a corrupted credential. It is required for TOTP too; PWN never
silently supplies consent.
Confirmation/serial flags without an account are rejected before login.

## Scope boundaries

YubiKey FIDO management is not a WebAuthn relying-party implementation. Website
passkey login still requires the browser's genuine security-key ceremony and
site enrollment; a generated OATH code must never be submitted to an SMS-only
challenge. PIV/OpenPGP key management does not export non-exportable keys or
magically replace TLS, SSH-agent or GPG-provider integrations.

Radio protocol keys, packet AES-CCM, TLS inspection certificates, OAuth PKCE,
artifact hashes, cloud KMS/HSM API clients and Jenkins private-key uploads are
not rewritten to use hardware-derived bytes. Their stored credentials can be
protected through Vault where appropriate.

Hardware-backed loot does not encrypt Recon's raw evidence/asset files, generic
tool-result artifacts, exports, or the filesystem as a whole. Those retain their
existing evidence-storage behavior and need separate access/at-rest protection.
`recon_run` advertises the same nonsecret hardware selector as `loot_query` for
harvested loot; metadata-only Vault queries do not unlock a device, but Dispatch's
separate output-redaction step can still require access to protected secrets.

Verification uses synthetic native connections and HMAC responses. Tests
exercise real Ruby encryption, authentication failures, selector validation
and persistence entry points. They are not evidence of a physical YubiKey,
live website authentication or every firmware variant.
