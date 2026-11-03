# YubiKey device operations

`PWN::Plugins::YubiKey` implements YubiKey application protocols in Ruby. It
talks to the device through HIDAPI and PC/SC (`::FFI` bindings to those host
libraries). It does not start `ykman`, another device CLI, a Python helper, or
any subprocess. It is not a WebAuthn relying party.

Hardware capability and firmware still decide which operations succeed. Fixture
tests are not physical-key interoperability, and this page does not claim every
model or firmware revision.

For encrypted configuration, credential storage, conversion and recovery, see
[YubiKey-backed vaults and authentication](YubiKey-Vaults.md).

## Dependency and discovery

`required_bins` is empty. Core setup does not install hardware packages. The
`hardware` profile maps optional host libraries (`hidapi`, `pcsc`), not an
executable. Loading the module does not open a device. `available?` only probes
those libraries. A missing library, a missing device, a permission failure and
an unsupported application are different conditions. Preflight reports
`FIDO native transport` and `PC/SC native transport` without discovering
hardware. See [Plugin Degradation](Plugin-Degradation.md#pwn-plugins-yubikey).

```ruby
require 'pwn'
yk = PWN::Plugins::YubiKey
yk.required_bins                       # => []
yk.available?(backend: 'hid')          # library probe; no device open
yk.devices                             # explicit listing; may be []
yk.info(serial: '12345678')            # example serial; replace locally
yk.otp(args: ['info'], serial: '12345678')
yk.help                                # public methods and option descriptions
yk.cli_help                            # local native help metadata, not a CLI process
yk.cli_help(path: %w[piv keys generate])
```

There is no `ykman:` path option. Executable paths, stdin, log files and inline
credential argv are rejected. Serial values must be decimal Strings; they are
not trimmed or coerced. Omit the serial only when selection is unambiguous.
PWN never chooses the first of several devices. `reader:` and `device_path:`
are mutually exclusive with each other and with `serial:` when more than one
is set. A caller-owned `connection:` stays open; PWN closes only handles it
opened.

## Native application coverage

Family methods take `args:` as an argv Array **after the family name**. With
no `args`, they return that family's local help metadata. `command(args:)`
takes the complete nonsecret argv, including the family name, and dispatches
to the matching Ruby application. It returns the application result; it does
not print or log it.

| Method | Application | Covered operations |
|---|---|---|
| `config` | management | USB/NFC application enablement, mode, lock code, timeouts, reset |
| `otp` | OTP | Slot inventory, Yubico OTP, static password, HOTP, HMAC challenge-response, settings, NDEF, swap, delete |
| `oath` | OATH | Account list/add/URI/import/rename/delete/code, access password, caller-owned cache, reset |
| `fido` | FIDO | PIN changes/verification, minimum PIN length, resident credential list/delete, fingerprints, UV/attestation policy, reset |
| `piv` | PIV | PIN/PUK/management key, key generation/import/export/move/delete/attestation, certificates, CSR and object management, reset |
| `openpgp` | OpenPGP | PIN/admin/reset code and retry policy, key import/attestation/touch policy, certificates, reset |
| `hsmauth` | HSM Auth | Asymmetric/symmetric/derived credentials, credential passwords, management protection, reset |
| `security_domain` | Security Domain | SCP key information, generation/import/export/deletion/allowlists and reset |
| `apdu` | smartcard | Explicit APDUs. Mutations require `confirm: true` |

Unknown command grammar is rejected. Do not pass a shell string. Use separate
argv elements: `args: ['keys', 'info', '9a']`, not `args: 'keys info 9a'`.
Short aliases and `--option=value` are rejected. `--` is available before a
positional identifier that begins with a dash.

### Confirmation, secrets and deadlines

Existing-slot HMAC calculation is the vault unlock path. Omitted `confirm` is
allowed. If `confirm` is present it must be literal `true`; `false`, `nil` and
`'true'` are rejected before any open.

Mutations, OATH calculation, provisioning and raw APDUs require literal
`confirm: true` before the device is opened. Confirmation does not guess
factory PINs, retry a blocked application, or delete a credential. Native OATH
does not delete or repair a corrupted credential. HOTP still advances its
counter. A password-protected OATH account needs an in-memory `password:` or
`access_key:`, or a caller `secret_provider`.

PINs, PUKs, management keys, access codes and OATH passwords stay in memory or
come from that provider. They are not argv, exception text, or logs. For a
private operator terminal, outside an agent request:

```ruby
yk.interact(
  args: %w[fido access change-pin], serial: '12345678',
  confirm: true, operator: true, timeout: 90
)
```

`interact` prompts on the controlling console, or on an explicitly supplied
readable and writable `terminal:` IO, then runs one native command. It returns
only `:completed`. It does not start a process, retain a transcript, or close
caller-owned IO. Run it outside curses and recorded tool sessions. Ruby does
not guarantee string zeroization.

`timeout:` is one finite positive budget in seconds, default **30**. It covers
open, secure-channel setup, authentication and commands. Remaining time is
what later exchanges receive; each step does not get a fresh 30 seconds.
`SCardCancel` does not universally interrupt `SCardTransmit`, and killing a
Ruby thread does not cancel a native driver call. After a timeout or
interruption, inspect device state before retrying a mutation.

Missing libraries, command failure, timeout, output limits and malformed
responses raise `DependencyError`, `CommandError`, `TimeoutError`,
`OutputLimitError` or `ResponseError`. These inherit from `YubiKey::Error`.
Missing consent raises `ConfirmationRequired`. Invalid caller values raise
`ArgumentError`. Errors do not include request bytes.

### Secure channel

`secure_channel:` is an explicit Hash, not a file of inline CLI keys. It
requires `scp:` (`:scp03`, `:scp11a`, `:scp11b` or `:scp11c`) and integer
`kvn:`. SCP03 also requires 16-byte in-memory `key_enc` and `key_mac`. A
failed secure-channel handshake does not fall back to plaintext. The owned
handle is still closed.

## Existing-slot HMAC challenge-response

```ruby
require 'securerandom'
challenge = SecureRandom.random_bytes(32) # Public challenge, not a provisioning key.
response = PWN::Plugins::YubiKey.challenge_response(
  challenge: challenge,
  slot: 2,
  serial: '12345678',
  timeout: 30
); nil # Suppress sensitive return-value echo in an interactive console.
```

`challenge:` is a raw Ruby String of **1–64 bytes**, not pre-encoded hex.
`slot:` is integer **1 or 2**, default **2**. The return value is exactly
**20 raw bytes**, encoding `ASCII-8BIT`. A touch-enabled slot requires a
physical touch before timeout. Missing or incompatible slots fail. This method
never programs, resets or repairs a slot. FIDO-only Security Key models cannot
provide this OTP HMAC operation.

The challenge is not placed on a child argv, because no child is started. Do
not use a password as the challenge. The HMAC response is sensitive key
material in the Ruby process.

## Explicit HMAC provisioning

Provisioning is separate from authentication and vault unlock. It **overwrites
the chosen slot**. The existing HMAC secret cannot be read back. Keep another
authentication method, and test recovery before discarding the new key.

```ruby
require 'securerandom'
secret_key = SecureRandom.random_bytes(20); nil
PWN::Plugins::YubiKey.provision_challenge_response(
  key: secret_key,
  serial: '12345678',
  slot: 2,
  confirm: true,
  timeout: 30
) # => :verified only after a fresh challenge matches the supplied key
```

`confirm: true` is required before open. An explicit serial, reader,
device path or caller-owned connection is required. `touch:` defaults to
`true`. Optional access codes are six raw bytes, supplied in memory, not at a
CLI prompt. The method checks a fresh challenge with Ruby OpenSSL HMAC-SHA1
and returns `:verified` only when that check passes. Touch the device when the
slot requires it. If programming succeeds and readback fails, the slot may
already have changed: inspect it before retrying. Do not assume rollback.

## Exact OATH retrieval

```ruby
code = PWN::Plugins::YubiKey.oath_code(
  account: 'Example:alice', # Exact identifier, not a substring.
  serial: '12345678',
  confirm: true,
  timeout: 30
); nil
```

The result is **6–8 decimal digits**, preserving leading zeros. The account
must be an exact control-free String of 1 to 64 bytes. Steam alphanumeric
codes are outside this method. `confirm: true` is required before open, including
for TOTP, because HOTP advances its counter and a protected account may
authenticate. Consent does not authorize deleting a corrupted credential.
Device errors do not fall back to a manual token.

## Authentication and interoperability limits

FIDO PIN, resident-credential and fingerprint management is **not website
login**. U2F/FIDO2/WebAuthn enrollment and assertions belong to the browser and
relying party. This module does not fabricate assertions. Submit an OATH code
only to a matching authenticator-code challenge, never an SMS-only or passkey
challenge. PayPal's SMS adapter rejects hardware OATH before login.

PIV and OpenPGP management do not supply a TLS client, SSH agent or GPG
middleware, and do not export non-exportable private keys. YubiHSM Auth
credentials are not a YubiHSM. Device and firmware errors stay errors. They do
not trigger reset, provisioning, a software-secret fallback, or repeated PIN
attempts.

## Offline verification

```text
bundle exec rspec spec/lib/pwn/plugins/yubikey_spec.rb spec/lib/pwn/plugins/yubikey_security_spec.rb spec/lib/pwn/plugins/yubikey_terminal_spec.rb
bundle exec rubocop lib/pwn/plugins/yubikey.rb spec/lib/pwn/plugins/yubikey_spec.rb spec/lib/pwn/plugins/yubikey_security_spec.rb spec/lib/pwn/plugins/yubikey_terminal_spec.rb
```

Those specs use synthetic connections and credentials, including an independent
RFC 2202 HMAC-SHA1 vector. They do not open a physical key, log in to a website,
or prove every firmware variant. USB/NFC, touch, PIN protection and real
relying-party login remain separate opt-in checks.

- [RFC 2202 HMAC test vectors](https://www.rfc-editor.org/rfc/rfc2202)
- [GlobalPlatform Card Specification](https://globalplatform.org/specs-library/card-specification/)
- [Yubico OTP protocol notes](https://developers.yubico.com/OTP/)
