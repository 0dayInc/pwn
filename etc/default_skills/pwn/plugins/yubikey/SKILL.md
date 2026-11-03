---
name: pwn-plugins-yubikey
description: Manage YubiKeys with explicit mutation guards.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  preserve: true
  module: PWN::Plugins::YubiKey
  source: pwn/plugins/yubikey.rb
---

# PWN::Plugins::YubiKey

Use the native Ruby wrapper around the official `ykman` executable. Never
provision, overwrite, repair or reset a slot as part of routine inventory,
authentication or vault access. See `documentation/YubiKey.md` for the device
contract and `documentation/YubiKey-Vaults.md` for storage/recovery integration.

## When to use

- Inventory and application status, or explicit YubiKey management requests.
- Binary HMAC-SHA1 challenge-response from an **already provisioned** OTP slot.
- OATH account listing and retrieval with consent for authentication, remembered-key
  cleanup, counter and credential-repair effects.
- Do not use device management as a substitute for browser WebAuthn ceremonies.

## Prerequisites

Install the official `yubikey-manager` separately. `required_bins` returns
`['ykman']`; `available?` probes `--version` without opening a device. Use a trusted
explicit `ykman:` path when PATH selection is unsuitable. The reviewed management
grammar is 5.9.1; automatic provisioning intentionally accepts only that version.
Use decimal String serials, integer slots 1 or 2, and a finite positive timeout.

## How to call

```ruby
PWN::Plugins::YubiKey.help
PWN::Plugins::YubiKey.available?
PWN::Plugins::YubiKey.devices
PWN::Plugins::YubiKey.info(serial: '12345678')
PWN::Plugins::YubiKey.otp(args: ['info'], serial: '12345678')
PWN::Plugins::YubiKey.cli_help(path: %w[piv keys generate])
```

Serials above are placeholders. Family methods take an `args:` argv Array after
the family name; omission returns official help. Use long options as separate
array elements, not a shell string or `--option=value`. `command` takes the full
management argv. All return raw output without logging it; successful output can
still contain secrets and must not be echoed into a transcript.

## Public methods

- `required_bins`, `available?`, `devices`, `info`, `cli_help`, `help`, `authors`
- `command`, `interact`, `config`, `otp`, `oath`, `fido`, `piv`, `openpgp`, `hsmauth`,
  `security_domain` (official **sd** family), `apdu`
- `challenge_response`, `provision_challenge_response`, `oath_code`

## Procedure

1. Identify the intended device and application with read-only inventory. Pin a
   serial when selecting a device; never choose the first key automatically.
2. Read the specific command's help. The wrapper guards the complete reviewed
   management tree, but model/firmware/interface support still belongs to ykman.
3. Obtain explicit `confirm: true` for every non-allowlisted operation, including
   resets, provisioning, authentication attempts, exports, OATH listing/calculation and
   all raw APDUs. Unknown commands stay rejected even after consent. Do not add
   `--force` merely to make a command succeed.
4. Keep credentials out of argv, environment variables, history and logs. Generic
   calls close stdin. Use `interact(args: ..., confirm: true)` only in a private
   operator terminal outside curses/recorded tool sessions. It bridges a native
   PTY, returns only `:completed`, restores terminal mode and descriptor status flags,
   and bounds total traffic and elapsed time, including human input. Its terminal
   must be readable and writable, including the Ruby wrapper mode; validation
   consumes no input and never closes caller-owned IO. Some upstream secret prompts
   are not masked. Never guess a PIN. Key imports and SCP11 use protected existing files;
   custom SCP03 import KIDs are refused before filename checks, even when the
   inline key string names an existing file. SCP11 file-import KIDs accept unsigned
   decimal, `0x` hex or `SCP11a`/`SCP11b`/`SCP11c` names, without coercion.
5. Read the exact result or device state after a mutation. A timeout is uncertain
   device state, not proof that nothing changed. Do not automatically retry.

### Existing HMAC slot

```ruby
challenge = SecureRandom.random_bytes(32)
response = PWN::Plugins::YubiKey.challenge_response(
  challenge: challenge, slot: 2, serial: '12345678', timeout: 30
); nil
```

Pass **raw 1–64 bytes**, not pre-encoded hex. The wrapper sends `otp calculate
SLOT HEX_CHALLENGE` and returns exactly **20 binary bytes**. Slot 2 is only a
selector default, never implicit provisioning. Touch the device if required;
the wrapper suppresses the CLI's stderr prompt. The challenge is public in argv;
never use a password as the challenge. Keep the response out of transcripts.

### Explicit provisioning

Only after inspecting the slot and obtaining consent, use
`provision_challenge_response(key: key_bytes, serial: serial, slot: 2,
confirm: true)`. `key_bytes` must be exactly 20 raw bytes acquired in local memory,
not a literal pasted into a console. The method checks ykman 5.9.1, supplies a
validated key/consent sequence through stdin without `--force`, enables touch,
and verifies a fresh random challenge with Ruby OpenSSL before returning
`:verified`. It overwrites the slot. Plan and test independent recovery before
discarding the key. Protected slots and other CLI versions require the separately
reviewed private-terminal workflow described in `documentation/YubiKey.md`.
No Ruby zeroization guarantee is made.

### Exact OATH

`oath_code(account: exact_identifier, serial: serial, confirm: true)` returns
6–8 digits, retaining leading zeros, or raises. It verifies a unique full
inventory identifier and the returned account label; substring-only, ambiguous,
changed-identity and nonnumeric output is refused. Official 5.9.1 has **no
--exact** option; `--single` alone is not exact matching. Confirmation is mandatory
for listing too: upstream may authenticate using a remembered key and delete/persist
that key if authentication fails, even without `--remember`. HOTP advances counters
and upstream code can delete corrupted credentials automatically. Do not treat
this as a read-only operation or use it for SMS/passkey
challenges. Password-protected OATH may require the private terminal workflow.

## Pitfalls

- Missing executable, unsupported device capability or malformed output is an
  error, not permission to reset, provision or fall back to a software key.
- `ykman script`, debug/traffic logging, secret argv fields, arbitrary stdin and
  unreviewed future commands are intentionally unavailable.
- Raw APDU bytes are visible in argv. Never put credentials in arbitrary payloads;
  the wrapper cannot infer their confidentiality.
- Noninteractive mutations needing prompts can abort/time out. Confirmation in
  Ruby does not bypass the CLI's own confirmation except the fixed provisioning
  stdin flow; no force flag is inserted.
- `timeout` defaults to 30 seconds and combined output to 1 MiB. Timeout/output
  failures kill the Unix child process group and reap the direct child. This is
  not a sandbox against a malicious executable escaping its process group.
- FIDO credential/PIN/fingerprint management is not website authentication.
  Browser and relying party must perform genuine security-key ceremonies.

## Verification

Run the paired offline suites:

```text
bundle exec rspec spec/lib/pwn/plugins/yubikey_spec.rb spec/lib/pwn/plugins/yubikey_security_spec.rb spec/lib/pwn/plugins/yubikey_terminal_spec.rb
bundle exec rubocop lib/pwn/plugins/yubikey.rb spec/lib/pwn/plugins/yubikey_spec.rb spec/lib/pwn/plugins/yubikey_security_spec.rb spec/lib/pwn/plugins/yubikey_terminal_spec.rb
```

Specs exercise real child processes with fake device executables, argument guards,
binary HMAC vectors, exact OATH parsing, validated provisioning, private PTY
prompts, descriptor/terminal restoration on success and failure, pre-spawn duplex
validation without consuming input, and cleanup. The
real 5.9.1 CLI's management help tree and Click stdin contract were separately
checked offline. None of this proves USB/NFC hardware, physical touches, PIN
protection, every firmware variant, or live website login. Report those boundaries.
