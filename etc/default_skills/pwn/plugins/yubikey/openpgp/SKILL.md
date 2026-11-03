---
name: pwn-plugins-yubikey-openpgp
description: Use native Ruby OpenPGP card operations through YubiKey APDUs.
---

# PWN::Plugins::YubiKey::OpenPGP

Native Ruby application logic using the shared `YubiKey::Protocol` APDU/TLV codec
and a caller-owned `Connection`. It does not run a CLI, start a subprocess, invoke
another interpreter, discover hardware at load time, or invent factory credentials.
Use `PWN::Plugins::YubiKey::OpenPGP.help` for all options.

## Safety and connection ownership

- Supply `connection:` with `descriptor[:protocol] == :apdu`. The caller owns
  connection selection, exclusive access and closing. Use a secure-connection
  wrapper when the selected device/interface requires SCP; never fall back to
  plaintext automatically.
- Pass literal `confirm: true` for **every** mutation, authentication attempt and
  private-key operation. A compatibility `--force` argument is not consent.
- Supply secrets as `pin:`, `admin_pin:`, `new_pin:`, `new_admin_pin:`, `reset_code:`
  or `key_password:`. A `secret_provider:` callable receives only the field Symbol
  for a required missing secret. Never put credentials in argv, logs or examples.
- Validate input, key type, algorithm, curve, firmware and card-advertised
  capabilities before authentication. Unsupported operations raise explicitly.
- Do not replay a mutation or crypto request after timeout, failed authentication,
  or a readback mismatch. A timeout can leave uncertain card state. Reset alone
  deliberately exhausts PIN counters, bounded by observed counters or the
  one-byte counter range during an explicitly requested corruption recovery.
- Replacing keys or changing algorithm attributes may erase existing keys.
  `fixed` and `cached-fixed` touch policy cannot be reversed without replacing
  the key. Factory reset does **not** restore the attestation key/certificate.
- PIN changes return freshly read retry counters and `credential_verified: false`:
  secret values cannot be read back. Use a separate explicitly confirmed
  `verify_pin` call if verifying the new credential is wanted.
- Secrets are not persisted by this module. Ruby/OpenSSL allocation and garbage
  collection do not guarantee zeroization of all temporary copies.

## Management leaf operations

`execute(args: [...], connection: connection, ...)` accepts the words **after**
`openpgp`. Empty args and the `access`, `keys`, `certificates` groups return local
help metadata without touching a connection. `operations` lists leaves only.

| Leaf | Native operation and evidence |
|---|---|
| `info` | SELECT, GET VERSION, application DO 6E, signature-counter DO 7A, KDF DO F9 when advertised |
| `reset` | Deliberate bounded PIN blocking, TERMINATE E6, ACTIVATE 44, fresh empty-key metadata readback |
| `access set-retries USER RESET ADMIN` | Admin VERIFY 83, F2, fresh C4 readback; NEO PIN-reset side effect reported |
| `access change-pin` | CHANGE REFERENCE DATA 24/81, fresh C4; requires `pin`, `new_pin` |
| `access change-admin-pin` | CHANGE REFERENCE DATA 24/83, fresh C4; requires `admin_pin`, `new_admin_pin` |
| `access change-reset-code` | Admin VERIFY, PUT DATA D3, fresh C4; requires `reset_code` |
| `access unblock-pin` | RESET RETRY COUNTER 2C, P1=0 with reset code or P1=2 with admin authorization |
| `access set-signature-policy always|once` | PUT DATA C4 with readback |
| `keys info SLOT` | Parsed algorithm, origin, fingerprint, generation time and UIF metadata |
| `keys set-touch SLOT POLICY` | GET/PUT DATA D6–D9, button byte 20, readback, fixed-policy protection |
| `keys import SLOT FILE|-` | Native OpenSSL key parsing, import template 4D/7F48/5F48, PUT DATA ODD DB/3FFF, public-key readback |
| `keys attest SLOT OUTPUT|-` | User VERIFY 81, proprietary 80/FB, certificate readback; SIG/DEC/AUT only |
| `certificates export SLOT OUTPUT|-` | SELECT DATA A5 and GET DATA 7F21, or attestation DO FC |
| `certificates import SLOT FILE|-` | Single PEM/DER X.509 parsing, certificate-limit validation, PUT DATA and exact DER readback |
| `certificates delete SLOT` | Empty PUT DATA, empty-slot readback |

Slots: `sig`, `dec`, `aut`, `att`; `enc` is an alias for `dec`. Touch policies:
`off`, `on`, `fixed`, `cached`, `cached-fixed`. Export/attest accept `--format PEM`
or `--format DER`; PEM is the default. Input `-` requires `key:` or `certificate:`
in memory, not stdin. Output `-` returns bytes, not stdout. Named output files are
created exclusively with mode 0600; existing paths are not overwritten.

## Typed cryptographic APIs

```ruby
pgp = PWN::Plugins::YubiKey::OpenPGP

# Read-only capability discovery and native OpenSSL public-key export.
supported = pgp.algorithms(connection: connection)
public_key = pgp.public_key(connection: connection, slot: :sig)

# Explicitly destructive on-card generation; returns an OpenSSL public key.
public_key = pgp.generate_key(
  connection: connection, slot: :sig, algorithm: :secp256r1,
  admin_pin: admin_pin, confirm: true
)

signature = pgp.sign(
  connection: connection, message: message, hash_algorithm: :sha256,
  pin: user_pin, confirm: true
)
authentication_signature = pgp.authenticate(
  connection: connection, message: challenge, pin: user_pin, confirm: true
)
plaintext_or_shared_secret = pgp.decipher(
  connection: connection, value: ciphertext_or_peer_public_key,
  pin: user_pin, confirm: true
)
# decrypt is an alias to the same decipher implementation.
```

- RSA signing sends DigestInfo through PSO 2A/9E9A; authentication uses INTERNAL
  AUTHENTICATE 88. RSA signatures are raw modulus-length bytes.
- ECDSA signs a SHA digest; card `r || s` is checked and converted to DER.
- Ed25519 sends the original message and returns raw 64-byte signatures.
  `prehashed: true` is rejected for Ed25519. Other signing methods can accept
  prehashed SHA-1/224/256/384/512 input of exactly the digest length.
- RSA decipher sends the zero padding indicator before a modulus-length
  PKCS1-v1_5 ciphertext. EC/X25519 decipher sends the A6/7F49/86 peer template
  and returns the **raw shared secret**, not a decrypted OpenPGP message.
- `verify_pin(mode: :signature|:extended|:admin, ...)` chooses PW1/81, PW1/82 or
  PW3/83. `unverify_pin` clears that reference on firmware 5.6 or newer.
- RSA2048/3072/4096, NIST P-256/384/521, secp256k1, Brainpool P256/P384/P512,
  Ed25519 and X25519 are recognized. Actual generation/import support comes
  from firmware restrictions and advertised FA entries, not merely host support.
- NEO RSA imports use CRT components; 4.4 FIPS firmware is limited to RSA2048.
  RSA generation is disabled on 4.2.0–4.3.4 vulnerable firmware.
- PKCS8 Curve25519 import extracts the inner 32-byte seed/scalar natively;
  X25519 reverses scalar bytes for the card. P-521 scalars use 66 bytes.
- PIN KDF supports card-advertised iterated-and-salted S2K with SHA256/SHA512,
  role-specific salts and bounded byte counts. Unknown KDFs never send plaintext.

## Verification and boundaries

Run the paired offline suite:

```text
bundle exec rspec spec/lib/pwn/plugins/yubikey/openpgp_spec.rb
bundle exec rubocop lib/pwn/plugins/yubikey/openpgp.rb spec/lib/pwn/plugins/yubikey/openpgp_spec.rb
```

Tests use the actual shared Protocol plus a strict synthetic Connection, literal
APDU fixtures, native OpenSSL keys, RFC seed material, host signature verification,
certificate parsing, public-key equality and ECDH equality. They cover command and
response chaining, version quirks, readback mismatch, malformed input, consent,
missing secrets, incorrect PIN and timeout without replay. They do not establish
USB/NFC interoperability or on-device behavior on every firmware/FIPS variant.

This is the card application layer, not a keyring, OpenPGP packet/ASCII-armor
encoder or signature/attestation trust-chain validator. RSA OAEP and symmetric
OpenPGP message decryption are not implied by the card PKCS1/ECDH primitives.

Protocol provenance: OpenPGP Card specification 3.4
(<https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf>),
Yubico YubiKey Manager 5.9.1 `yubikit/openpgp.py` and
`ykman/_cli/openpgp.py` (<https://github.com/Yubico/yubikey-manager>).
The cached official sources were consulted read-only, never used as runtime
backends. Source attribution and the reference BSD license are retained in Ruby.
