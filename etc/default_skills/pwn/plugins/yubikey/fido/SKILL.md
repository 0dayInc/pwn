---
name: pwn-plugins-yubikey-fido
description: Use when managing native FIDO and U2F operations.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  preserve: true
  module: PWN::Plugins::YubiKey::FIDO
  source: pwn/plugins/yubikey/fido.rb
---

# Native FIDO/U2F

Use `PWN::Plugins::YubiKey::FIDO` for CTAP2 management and caller-controlled
credential operations. Application logic and CBOR are Ruby; cryptography uses
Ruby OpenSSL and host entropy. No executable, interpreter worker or CBOR gem is
required. CTAPHID framing and shared-library device I/O belong to `Transport`.

## When to use

- Read authenticator capabilities, manage PINs, discoverable credentials,
  fingerprints, always-UV and enterprise-attestation configuration.
- Run low-level makeCredential/getAssertion or U2F registration/authentication
  with an RP/application and client-data hash supplied by the caller.
- Do not treat this module as a browser or WebAuthn relying-party server. It does
  not invent origins, approve RP IDs or verify server challenges/signatures.

## Prerequisites and safety

Obtain an explicitly selected FIDO connection from `YubiKey::Transport.open`
with `application: :fido`. Serial-less Security Keys are valid; select them by
exact device path/reader or unambiguous inventory, never an OTP serial guess.
HID supports CTAP/U2F; APDU supports FIDO AID selection, NFC CTAP, command chaining,
GET RESPONSE, keepalive and cancellation. Read getInfo to negotiate actual
options and PIN protocol 2 or 1; do not infer support from the model name.

Every authentication, signature/counter operation and mutation requires literal
`confirm: true`. `--force` is only an accepted compatibility flag; it grants no
consent. `info`, retry counters and fingerprint sensor information do not require
consent. Help groups are local and do not need a connection.

Supply `pin:` and `new_pin:` as in-memory Strings, or an explicitly provided
`secret_provider:` callable receiving `:pin`/`:new_pin`. Never put these in args,
process arguments, environment variables, files or transcripts. There is no
factory PIN, default prompt, automatic PIN retry or automatic reset retry.
Sessions erase owned secret copies on completion, but Ruby/OpenSSL cannot promise
that every temporary allocation is zeroized. Caller-owned Strings are untouched.

## Management calls

```ruby
fido = PWN::Plugins::YubiKey::FIDO
fido.execute(args: [])                         # local leaf catalog
fido.execute(args: ['access'])                 # local group help
fido.execute(connection: connection, args: ['info'])
fido.perform(connection: connection, operation: :pin_retries)
# secret_provider below is an operator-supplied private callable, not a prompt default.
fido.execute(connection: connection, args: %w[access verify-pin],
             secret_provider: secret_provider, confirm: true)
```

Implemented leaf paths (args exclude the `fido` prefix):

| Path | Additional in-memory inputs / behavior |
|---|---|
| `info` | Actual CTAP getInfo, or U2F version/capabilities |
| `reset` | One reset command; firmware power-up/touch window still applies |
| `access change-pin` | `new_pin:`, plus `pin:` when already configured; initializes only if getInfo reports no PIN |
| `access change-pin --u2f` | YubiKey 4 FIPS vendor U2F PIN command, capability-probed |
| `access verify-pin` | `pin:`; verifies by obtaining and discarding a token, no fabricated RP |
| `access force-change` | Config permission; requires existing PIN and setMinPINLength |
| `access set-min-length LENGTH` | Optional repeatable `--rp-id RPID`; minimum cannot decrease |
| `credentials list` | PIN/UV permission 0x04; exhausts every RP and credential; checks totals and duplicates |
| `credentials list --csv` | Returns CSV in memory; no output file is opened |
| `credentials delete HEX_ID` | Complete exact credential ID; no ambiguous prefix matching |
| `fingerprints list` | Permission 0x08; returns template IDs and names |
| `fingerprints add [NAME]` | Bounded capture loop and optional friendly name |
| `fingerprints rename HEX_ID NAME` | Exact template ID and UTF-8 friendly name |
| `fingerprints delete HEX_ID` | Exact template ID |
| `config toggle-always-uv` | Permission 0x20 if a PIN/UV token is required |
| `config enable-ep-attestation` | Requires advertised enterprise-attestation capability |

Local groups: root, `access`, `credentials`, `fingerprints`, `config`.
`operations` lists leaf paths only; variants above are not extra leaf operations.
PIN verification selects a supported non-RP management permission when scoped
tokens are advertised, or scopes getAssertion permission to an explicitly supplied
`rp_id:`. Without either it uses legacy getPINToken, never an invented website.
An authenticator disabling legacy tokens and exposing no non-RP permission needs
the caller's `rp_id:`. Built-in UV is not accepted as proof of PIN verification.
`perform(operation: :update_credential, credential_id: binary_id, user: user_hash,
...)` implements CTAP2.1 updateUserInformation; `user['id']` must be the existing
user ID. Preview credential management supports list/delete, not user update.

All native IDs/hashes are **binary Strings** (`.b`); text is valid UTF-8.
Hex CLI selectors are decoded only after strict even-length hex validation.
PINs are not normalized or silently truncated. Standard CTAP PINs require at
least the advertised minimum and at most the advertised byte limit (63 by
default), with no NUL. Old FIPS U2F requires at least 6 characters and permits
at most 32 encoded bytes. A newer advertised PIN limit does not waive the CTAP
255-byte bound on the block-padded PIN plaintext.

## Credential operations

```ruby
# client_data_hash is a 32-byte SHA-256 digest produced by the caller's ceremony.
attestation = fido.make_credential(
  connection: connection, confirm: true, client_data_hash: client_data_hash,
  rp: { 'id' => relying_party_id, 'name' => relying_party_name },
  user: { 'id' => user_id.b, 'name' => user_name },
  secret_provider: secret_provider
)
assertions = fido.get_assertion(
  connection: connection, confirm: true, rp_id: relying_party_id,
  client_data_hash: client_data_hash,
  allow_list: [{ 'type' => 'public-key', 'id' => credential_id.b }]
)
```

makeCredential accepts `key_params:` (default ES256), `exclude_list:`,
`extensions:`, `authenticator_options:` and `enterprise_attestation:` (1 or 2).
getAssertion accepts `allow_list:`, `extensions:` and `authenticator_options:`;
it returns an Array containing all advertised assertions, using getNextAssertion.
Use `pin:`/`secret_provider:` for PIN verification, or literal `uv: true` for
configured built-in UV and a permission-scoped token. Permission tokens bind
makeCredential/getAssertion to the exact caller RP ID. No-PIN/non-UV requests
remain possible where the authenticator permits them; the device enforces policy.
CTAP2.0 preview commands use the legacy PIN token when scoped tokens are absent.

`u2f_register(connection:, confirm: true, client_data_hash:, app_id_hash:)`
returns the raw public key, key handle, attestation certificate and signature.
`u2f_authenticate(..., key_handle:)` returns presence, counter and signature.
Literal `check_only: true` interprets only defined U2F recognition statuses.
These return cryptographic material, **not a server authentication verdict**.
The caller must verify challenge, RP/application hash, origin policy, flags,
algorithm, signature, attestation trust and counter semantics before accepting it.

## Bounds, cancellation and recovery

- `timeout:` is one finite positive operation budget, default 30 seconds.
  `cancelled:` is a callable, forwarded to Transport as well as checked between
  exchanges; `on_keepalive:` receives status 1 or 2. Callback exceptions propagate.
- `max_records:` defaults to 1024, maximum 16384. Counts are assertions, not hints:
  excessive, duplicate, inconsistent or prematurely ended lists fail explicitly.
- Enrollment uses `capture_timeout_ms:` (default 10000), `max_samples:` (default
  128), and optional `on_sample:` callable receiving template ID, status and
  remaining samples. Intermediate bad captures are reported; PIN attempts are not
  repeated. Failure attempts one separately bounded enrollment cancel, without
  deleting any credential. A failed cleanup cannot replace the original error.
- `perform(operation: :bio_sensor_info)` is unauthenticated. Explicit
  `perform(operation: :cancel_enrollment, confirm: true)` cancels enrollment.
- If enrollment completes but naming fails, `EnrollmentError#template_id` names
  the already-created template. Rename that template; do not enroll again or
  assume a rollback. A transport timeout can leave device state uncertain.
- A connection is caller-owned. Use it exclusively for the whole operation; do
  not interleave concurrent enumeration, PIN or enrollment workflows. Close it in
  the caller's ensure block. A closed/error transport cannot promise cleanup.
- U2F-only authenticators report U2F capabilities. CTAP2-only management fails
  explicitly. FIPS-only PIN/reset commands are implemented, not substituted for
  ordinary U2F devices. Physical touch/reset timing is never simulated.

## CBOR and crypto verification

`FIDO::CBOR.encode(value:)` / `.decode(data:)` use CTAP canonical major-type
ordering, minimal integer/length encodings, 32-level depth, 16384-item and 1 MiB
bounds. Map keys are integer/text; byte strings use ASCII-8BIT encoding. Reject
indefinite lengths, duplicate keys, noncanonical maps, invalid UTF-8, trailing
bytes, tags and floating-point values rather than coercing them.

Protocol 1 derives SHA256(ECDH-x), zero-IV AES-256-CBC and 16-byte HMAC outputs.
Protocol 2 derives independent HKDF-SHA256 HMAC/AES keys using the CTAP labels,
uses a fresh host-random IV prefix and 32-byte HMAC. Validate COSE EC2/P-256/-25
key agreement points before ECDH. No device OTP output supplies entropy.

Run the paired RSpec offline with an isolated HOME and the repository's normal
Ruby bundle; only Connection or native I/O fixtures may be faked. Keep independent
RFC8949/NIST/RFC4231/P-256/KDF vectors, both PIN protocols, complete public
management paths, response errors and cancellation tests. Passing fixtures prove
host protocol behavior, not physical-device or platform interoperability.

References used for the protocol contract:

- [FIDO CTAP 2.1 proposed standard, 2021-06-15](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html)
- [U2F raw message formats 1.2](https://fidoalliance.org/specs/u2f-specs-1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html)
- [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) and [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231)
- Official `python-fido2` 2.2.1: `cbor.py`, `ctap1.py`, `pcsc.py`,
  `ctap2/{base,pin,credman,bio,config}.py`; YubiKey Manager 5.9.1 `ykman/fido.py`
  and its FIDO command module. These were read-only interoperability references,
  not runtime dependencies; the Ruby implementation is independently written.
