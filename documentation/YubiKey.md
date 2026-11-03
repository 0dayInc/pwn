# YubiKey device operations

`PWN::Plugins::YubiKey` is a native Ruby wrapper around Yubico's official
`ykman` executable. It is not a USB driver, a replacement for Yubico's CLI, or a
WebAuthn relying party. The command grammar is based on **YubiKey Manager
5.9.1**. Hardware capability and firmware still determine which commands work.

For encrypted configuration, credential storage, conversion and recovery, see
[YubiKey-backed vaults and authentication](YubiKey-Vaults.md).

## Dependency and discovery

Install the official **yubikey-manager** package using Yubico's installation
instructions or your platform package manager. PWN reports `ykman` as an optional
hardware tool; merely loading this module does not install software or access a
device. The official executable has its own Python/native-library dependencies;
PWN does not ship a Python helper. PC/SC, USB permissions and enabled device
interfaces must be configured locally as appropriate.

```ruby
require 'pwn'
yk = PWN::Plugins::YubiKey
yk.required_bins                     # => ['ykman']
yk.available?                        # --version only, no device operation
yk.devices                           # decimal serial Strings, or []
yk.info(serial: '12345678')           # example serial; replace locally
yk.otp(args: ['info'], serial: '12345678')
yk.help                              # all public methods and option descriptions
yk.cli_help                          # official --full-help, including sd and apdu
yk.cli_help(path: %w[piv keys generate])
```

`ykman: '/trusted/path/to/ykman'` selects an executable explicitly. Do not load
executable paths from untrusted vault metadata. Serial values must be decimal
**Strings**; they are not trimmed, coerced or repaired. Omit the serial only when
device selection is unambiguous. PWN never chooses the first of several devices.
`reader:` selects a smartcard reader instead and cannot be combined with `serial:`;
it is not supported by the upstream `list` command.

## Management coverage

Every family method accepts `args:` as an argv Array **after the family name**.
With no `args`, it returns that family's official help. `command(args:)` accepts
the complete management argv after global selection/security options. It returns
raw binary-tagged stdout; it does not print or log the result.

| Method | Official family | Covered management operations |
|---|---|---|
| `config` | `config` | USB/NFC application enablement, mode, lock code, timeouts, reset |
| `otp` | `otp` | Slot inventory, Yubico OTP, static password, HOTP, HMAC/TOTP challenge-response, settings, NDEF, swap, delete |
| `oath` | `oath` | Account list/add/URI/import/rename/delete/code, access password, remembered-password state, reset |
| `fido` | `fido` | PIN changes/verification, minimum PIN length, resident credential list/delete, fingerprints, UV/attestation policy, reset |
| `piv` | `piv` | PIN/PUK/management key, key generation/import/export/move/delete/attestation, certificates, CSR and object management, reset |
| `openpgp` | `openpgp` | PIN/admin/reset code and retry policy, key import/attestation/touch policy, certificates, reset |
| `hsmauth` | `hsmauth` | YubiHSM Auth asymmetric/symmetric/derived credentials, credential passwords, management protection, reset |
| `security_domain` | **`sd`** | SCP key information, generation/import/export/deletion/allowlists and reset |
| `apdu` | `apdu` | Explicit raw APDUs, application selection, full-APDU mode and response formatting |

The wrapper recognizes the complete 5.9.1 management command tree, including
hidden `sd` and `apdu`. It intentionally does **not** run `ykman script`, arbitrary
Python, diagnostic logging, inline credential options, or unknown future commands.
New command grammar must be reviewed before extending the allowlist. All known
commands remain discoverable through `cli_help`. Protected prompts use the
explicit private-terminal `interact` method rather than secret command arguments.

Use **long options as separate argv elements**. Short aliases and `--option=value`
are rejected to avoid credential-alias ambiguity; `--` is available before a
positional identifier beginning with a dash. Do not pass shell command strings.
For example, `args: ['keys', 'info', '9a']`, not `args: 'keys info 9a'`.

### Confirmation and execution boundaries

Only a narrow read-only allowlist runs without confirmation: device inventory,
basic application information, interface `--list`, HSM Auth credential listing,
canonical help/version calls, and validated HMAC calculation. Other operations
require **literal `confirm: true`**. This includes key provisioning, reset,
authentication attempts, local exports, unknown commands, OATH account listing
and code generation, and **every raw APDU**, even an APDU the
caller believes is a read. Confirmation does not make unknown grammar acceptable.

OATH account listing requires consent even without `--remember`: upstream
authenticates with a remembered credential and may delete and persist that
remembered key on authentication failure before prompting.
Device discovery may still update ykman's noncredential local device-history cache;
the allowlist is not a guarantee of no host filesystem writes.

PWN never adds `--force` to destructive operations. A caller may explicitly supply
that flag after consenting, but `confirm: true` alone does not automatically answer
the CLI's prompts. Normal commands close stdin and capture output; they are not
interactive terminal sessions. A prompt may abort or time out. Do not retry an
uncertain mutation blindly: inspect device state first. The one automated secret
input path is the fixed, version-checked HMAC provisioning method below.

- Execution uses argv vectors, never a shell. Arguments and outputs are bounded.
  A child-only `0077` umask restricts newly created output files; it does not
  repair permissions on existing files or suppress the CLI's generated secrets.
- `timeout:` is a finite positive number of seconds, default **30** per child.
  OATH retrieval shares one budget across inventory and calculation; explicit
  provisioning uses a separate budget for each of its three subprocesses.
- `max_output:` defaults to **1,048,576 bytes**, counting both stdout and stderr.
  Exceeding it terminates the operation rather than returning partial output.
- Cleanup sends TERM, then KILL to the child's process group and reaps the direct
  child. Unix process-group semantics are required. This is not a sandbox for a
  malicious replacement executable or a process that deliberately escapes its group.
- Missing executable, nonzero exit, timeout, output limit and malformed responses
  raise `DependencyError`, `CommandError`, `TimeoutError`, `OutputLimitError` or
  `ResponseError`. These inherit from `YubiKey::Error`. Guard failures use
  `ConfirmationRequired`; invalid caller values use `ArgumentError`.
- Errors suppress stdout/stderr, argv and underlying OS exception causes. Successful
  output can still contain generated keys, account identifiers or OTPs: do not
  print, persist, put into agent transcripts, or send it to a logger.

### Credential and secure-channel handling

Do not pass PINs, PUKs, passwords, management/access/lock keys, OTP seeds or OATH
URIs in argv. Their known options and positional slots are rejected even with
confirmation. Unknown Ruby options, including arbitrary stdin, are rejected too.
Key imports take existing key **file paths**, not inline secret bytes; protect
those files and remove them according to your organization's retention policy.

For protected commands, use `interact` in a **private local operator terminal**,
omit credential arguments and answer the official CLI's prompts. Obtain specific
consent first. For example, after approving a PIN change on the selected device:

```ruby
yk.interact(
  args: %w[fido access change-pin], serial: '12345678',
  confirm: true, timeout: 90
)
```

It bridges a native PTY to the controlling console (or an explicitly supplied
readable **and** writable `terminal:` IO), restores terminal mode and original
file-descriptor status flags on exit, and returns only `:completed`.
There is no retained transcript or returned credential output. The byte limit
counts total terminal traffic, and the timeout includes human input. Timeout or
interruption kills the child process group and reaps the direct child, without
retrying a potentially completed write. Nonterminal and one-way IO callers fail
before spawning, including Ruby read-only/write-only wrappers of duplex descriptors.
Validation does not consume terminal input, and caller-owned IO is never closed.
Run outside active curses screens and recorded tool sessions; this is an
operator workflow, not an automatic agent prompt handler. The bridge does not
mask prompts that upstream itself echoes or guarantee Ruby-memory zeroization.

The same method accepts `args: %w[otp --access-code - settings 2
--delete-access-code]`: only the literal dash is accepted for that access-code
option, so the actual code is requested at the private prompt. Ordinary `command`
continues to close stdin. Equivalent official command shapes are:

```text
ykman --device SERIAL piv access change-pin
ykman --device SERIAL fido access change-pin
ykman --device SERIAL oath accounts add 'Issuer:account'
ykman --device SERIAL otp --access-code - settings 2 --delete-access-code
```

Check the installed command's `--help` first. Do not put literal credentials in
shell history or transcripts. Some upstream secret prompts are **not masked**;
turn off terminal recording and screen sharing. Do not guess PINs: failed attempts
can consume retries or block the application. `--remember` writes host keyring
state and requires explicit consent.

For file-based SCP11, pass `scp: [private_key_path, certificate_path]`,
`scp_ca: ca_path`, and, where needed, `scp_sd: [kid, kvn]` /
`scp_oce: [kid, kvn]`. References are two integer bytes. File order follows Yubico's
private-key/certificate-chain, leaf-last convention. No `scp-password` argument is
accepted; encrypted-key prompting belongs in the operator terminal.

**SCP03 limitation:** upstream 5.9.1 accepts custom SCP03 key material only inline
for global `--scp` and `sd keys import`; this wrapper refuses that exposure. Import
KID 1 and its alternate spellings are rejected before filename checks, even if a
file has the same name as the inline keys. File imports accept only SCP11 KIDs
`0x10`, `0x11`, `0x13`, `0x15`, `0x20`–`0x2f`, their unsigned decimal spellings,
or `SCP11a`/`SCP11b`/`SCP11c` names. Hex/name case and numeric leading zeros are
preserved; other spellings are rejected, not coerced. Custom SCP03 provisioning is
not provided through this credential-safe wrapper. Do not work around it by
putting keys into APDU argv. Raw APDUs are for nonsecret command bytes only; the
wrapper cannot infer the confidentiality of arbitrary protocol payloads.

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

`challenge:` is a raw Ruby String containing **1–64 bytes**, including NUL or
non-UTF-8 bytes. PWN encodes it once as hex for the official command:

```text
ykman --device SERIAL otp calculate SLOT HEX_CHALLENGE
```

`slot:` is integer **1 or 2**, default **2**. The return value is exactly **20 raw
bytes**, encoding `ASCII-8BIT`, not hex and not a time-based OTP. Decorated,
truncated, multiple or malformed responses are rejected. A touch-enabled slot
requires a physical touch before timeout; the wrapper does not print the CLI's
touch prompt. Missing or incompatible slots fail. **This method never programs,
resets, repairs or changes a slot**, and a default of slot 2 does not provision it.
FIDO-only Security Key models cannot provide this OTP HMAC operation.

The public challenge is visible in child argv. Never use a password or secret
key itself as a challenge. The slot secret is not exported during calculation;
the HMAC response nevertheless is sensitive key material in the Ruby process.

## Explicit HMAC provisioning

Provisioning is separate from authentication, inventory and vault access. It
**overwrites the chosen slot** and can permanently break existing uses of that
slot. Establish recovery before programming a device; a key's existing HMAC
secret cannot be read back. Preserve another independent authentication method.

1. Use `devices`, `info` and `otp(args: ['info'])` with the exact serial. Inspect
   the target slot and its current purpose; never infer that slot 2 is unused.
2. Obtain explicit approval for that serial/slot. Securely generate or recover a
   20-byte key in local memory. Decide whether an independent recovery token must
   be provisioned with that same key **before** discarding it.
3. With **ykman 5.9.1**, run the dedicated method from trusted local Ruby code:

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

   The method verifies the CLI version, sends the hex key and a fixed affirmative
   confirmation **through stdin**, and invokes `otp chalresp --touch 2` without a
   key argv or `--force`. It then requests a fresh 32-byte challenge and checks the
   response against Ruby OpenSSL HMAC-SHA1. **Touch the device for verification.**
   It requires an explicit serial and always enables touch. Protected slots that
   need an access code use the terminal workflow instead.
4. If version validation fails, no provisioning command runs. If provisioning or
   readback fails later, the slot may already have changed: inspect it before
   retrying. Do not assume rollback. Test a recovery token independently.
5. Discard the in-memory key only after the chosen recovery procedure is complete.
   Ruby does not guarantee zeroization of strings and copies, and the REPL may
   retain history/return values; this is why literals and return-value echo are
   inappropriate for real keys.

Other CLI versions require a separately reviewed prompt contract or a private
operator terminal. For the latter, inspect `ykman otp chalresp --help`, then run
`ykman --device SERIAL otp chalresp --touch 2` **without a KEY argument** and supply
the key at the prompt. Upstream may echo it. Its `--generate` option also prints
the generated key, so it is not a secrecy-preserving shortcut.

## Exact OATH retrieval

```ruby
code = PWN::Plugins::YubiKey.oath_code(
  account: 'Example:alice', # Exact identifier returned by OATH accounts list.
  serial: '12345678',
  confirm: true,
  timeout: 30
); nil
```

The result contains only **6–8 decimal digits**, preserving leading zeros. Missing,
ambiguous, changed-identity, multiline and nonnumeric results fail closed. Steam
alphanumeric codes are deliberately outside this convenience API; the general
OATH interface still exposes official CLI output.

There is **no `--exact` option in official 5.9.1**. `--single` ensures one match but
still accepts substrings and removes the account label. Therefore this method:

1. Lists accounts with `--show-hidden --oath-type` and requires exactly one
   case-sensitive complete identifier match.
2. Runs `oath accounts code --show-hidden -- ACCOUNT`, keeping the result label.
3. Checks that exactly one output row has the requested identifier and numeric
   code before returning only the digits. It does not use unsupported flags or
   falsely describe substring matching as exact matching.

`confirm: true` covers both inventory and calculation. Even `accounts list` may
authenticate with a remembered credential and delete/persist an incorrect
remembered key, without `--remember`. Consent is required even for TOTP:
upstream 5.9.1 `accounts code` may **automatically delete a corrupted credential**
after a memory error. HOTP also
advances its counter. This is not a read-only operation. Password-protected
applications that cannot unlock through the CLI's existing local state require
the private operator-terminal workflow; do not provide passwords in argv.
Two subprocesses are not an atomic device transaction. Do not concurrently change
accounts or swap devices; output identity is rechecked, but prior side effects
cannot be undone. Pin the serial and complete any required touch within timeout.

## Authentication and interoperability limits

FIDO PIN/resident-credential/fingerprint management is **not website login**.
Real U2F/FIDO2/WebAuthn enrollment and assertions belong to the browser and relying
party, including origin/RP binding, user presence and policy. This module neither
fabricates assertions nor bypasses security-key prompts. OATH codes must only be
submitted to a site's matching authenticator-code challenge, never an SMS-only
or passkey challenge.

PIV/OpenPGP management does not supply a TLS client, SSH agent or GPG middleware,
and does not export non-exportable private keys. YubiHSM Auth credentials are
not a replacement for a YubiHSM device. Device/firmware/application errors stay
errors rather than triggering reset, provisioning, software-secret fallback or
repeated PIN attempts.

## Offline verification and sources

```text
bundle exec rspec spec/lib/pwn/plugins/yubikey_spec.rb spec/lib/pwn/plugins/yubikey_security_spec.rb spec/lib/pwn/plugins/yubikey_terminal_spec.rb
bundle exec rubocop lib/pwn/plugins/yubikey.rb spec/lib/pwn/plugins/yubikey_spec.rb spec/lib/pwn/plugins/yubikey_security_spec.rb spec/lib/pwn/plugins/yubikey_terminal_spec.rb
```

The specs use executable Ruby fakes and synthetic credentials, including an
independent RFC 2202 HMAC-SHA1 vector. They exercise real process execution,
timeout/process-group cleanup, errors, argument guards, binary conversion,
exact OATH parsing, validated provisioning/readback, native PTY prompts and
terminal mode/status-flag restoration on success and failure, and pre-spawn duplex
validation without consuming input. No test opens a physical key,
logs in to a website or uses live credentials.

An isolated official 5.9.1 CLI was additionally exercised with `--help` at all
**124 recognized management command/group paths**. Its real Click provisioning
callback was exercised with a fake device session to validate the stdin contract.
These establish CLI compatibility, **not physical-device acceptance**. Hardware
USB/NFC, touches, PIN protection, firmware variants and real relying-party login
remain separate opt-in validation.

- [Yubico YubiKey Manager documentation](https://docs.yubico.com/software/yubikey/tools/ykman/)
- [Official 5.9.1 OTP CLI source](https://github.com/Yubico/yubikey-manager/blob/5.9.1/ykman/_cli/otp.py)
- [Official 5.9.1 OATH CLI source](https://github.com/Yubico/yubikey-manager/blob/5.9.1/ykman/_cli/oath.py)
- [OATH corrupted-credential repair](https://github.com/Yubico/yubikey-manager/blob/5.9.1/ykman/oath.py)
- [CLI piped-input behavior](https://github.com/Yubico/yubikey-manager/blob/5.9.1/ykman/_cli/util.py)
- [Security Domain CLI](https://github.com/Yubico/yubikey-manager/blob/5.9.1/ykman/_cli/securitydomain.py)
- [RFC 2202 HMAC test vectors](https://www.rfc-editor.org/rfc/rfc2202)
