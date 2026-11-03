---
name: pwn-plugins-yubikey-piv
description: Native PIV APDU keys, certificates, objects and crypto.
---

# PWN::Plugins::YubiKey::PIV

Use native Ruby/OpenSSL PIV operations through the parent YubiKey connection and
Protocol codec. No command-line helper, Python runtime, device discovery during
load, or private-key export is used.

## Entry points

- `execute(connection:, args:, ...)`: family-relative commands (`keys generate`,
  `certificates request`, `objects export`, `access change-pin`, and so on).
  Empty args or an access/keys/certificates/objects group return local help.
- `operations`: implemented leaf catalog, separate from group/help paths.
- `verify_pin(connection:, pin:, confirm: true)` and
  `authenticate(connection:, management_key:, confirm: true)`.
- `sign(connection:, slot:, algorithm:, message:, pin:, confirm: true)` supports
  RSA PKCS1/PSS, P-256/P-384 ECDSA, and Ed25519. `hash_algorithm:` defaults SHA256;
  `prehashed: true` accepts a correctly sized digest except Ed25519 always uses
  the complete message. RSA `padding:` is `:pkcs1` or `:pss`.
- `decrypt(connection:, slot:, ciphertext:, padding: :oaep, pin:, confirm: true)`
  supports RSA OAEP (hash, MGF1 hash, label), PKCS1 and explicit raw `:none`.
- `calculate_secret(connection:, slot:, peer_public_key:, pin:, confirm: true)`
  supports P-256/P-384 and X25519. Treat its output as raw KDF input, not an
  application encryption key.

## Consent, secrets, and output

Every mutation/authentication/private-key operation requires literal
`confirm: true`. `--force` never grants consent. PINs, PUKs, management keys,
passwords and replacements belong in options, never argv. Management keys are
raw binary bytes, not hex strings. A `secret_provider` callable can supply a
missing field by Symbol, after consent. Factory credentials are never guessed.

`-` as an input filename requires binary `input:`; no implicit terminal read.
`-` as output returns raw bytes. Named output requires confirmation and is
created exclusively with mode 0600; existing files are never overwritten.
`keys export` only returns the public key. `public_key_source:` explicitly
selects `:metadata` (default, firmware 5.3+), `:attestation` (4.3+) or
`:certificate`. There is no fallback after a failed key source.

Firmware gates include ROCA-vulnerable RSA generation, FIPS restrictions,
PIN/touch policies and biometric MATCH policy detection. RSA3072/RSA4096,
Ed25519/X25519 and move/delete require firmware 5.7+. AES management keys require
5.4+. Supply `fips_restrictions: true` when device capability metadata identifies
a newer FIPS device.

## Management and lifecycle

`access change-management-key` accepts `new_management_key:` and `--algorithm`
TDES/AES128/AES192/AES256. `--protect` stores the new key in PIN-protected PIVMAN
data. Explicit `use_protected_key: true` enables PIN-protected or legacy
PIN-derived management authentication; corrupt metadata is never repaired
implicitly. Unprotected `--generate` requires `secret_sink.call(field, bytes)`
to securely retain the generated key before installing it. Returned status
never includes the management key.

Key generation/import accepts PIN and touch policies. Import supports native
OpenSSL PEM/DER private keys, including encrypted inputs through `password:`.
Certificates support PEM/DER and PKCS12 import, compressed storage, device-signed
self-signed certificates and PKCS10 requests. The host builds ASN.1, but only
the device private-key operation signs the TBS/request bytes. The result is
verified with OpenSSL before storage/return. Signed or corrupt CHUID objects
are left intact. Certificate changes update unsigned CHUID GUIDs unless
`--no-update-chuid` is passed. `objects generate` accepts CHUID and CCC only.
Object writes are read back and compared before reporting success. Multi-APDU
operations are not transactions: failures must be reconciled, not auto-retried.

## Reset

`execute(args: ['reset'], confirm: true)` only sends reset after checking for
enrolled biometrics; it never guesses or blocks PINs/PUKs. Firmware requires
both retry counters to be blocked. To explicitly authorize the destructive
blocking process, also supply `block_retries: true`. This sends deliberately
invalid empty padded PIN and PUK references until their counters reach zero,
with bounded attempts and decreasing-counter checks, then resets PIV. This
wipes application data and restores factory references; biometric/full-device
reset restrictions are not bypassed. Never enable blocking as an automatic
recovery action.

## Implementation verification rules

- Encode RSA public material as SubjectPublicKeyInfo with rsaEncryption and NULL
  parameters. Generic OpenSSL loading can interpret a bare two-INTEGER RSA
  public sequence as DH parameters; the RSA generation/import regressions catch
  this ambiguity.
- For RSA PKCS1 decryption on OpenSSL 3.2+, explicitly disable implicit rejection
  for the ephemeral padding key. Otherwise an invalid block can return synthetic
  plaintext instead of an exception. The paired negative test requires failure.
- Keep temporary biometric PINs within one selected session: retain a
  `PIV::Session.new(connection: connection, confirm: true)` and call its
  `verify_uv(request_pin: true)` and `verify_temporary_pin(bytes)` methods on
  that same instance. Do not assume reselection preserves a temporary PIN.
- Separate the transport `serial:` selector from `certificate_serial:` when
  constructing certificates. Tests preserve a zero-prefixed transport selector.

## Offline verification and protocol references

The paired RSpec uses literal APDU fixtures and a synthetic card boundary,
independently reconstructs imported private keys, and validates actual RSA,
ECDSA, Ed25519, ECDH, X25519, certificate and CSR cryptography with OpenSSL.
It never accesses a physical reader, network, credentials or live home state.
These fixtures demonstrate host protocol behavior, not physical interoperability.

Wire specifications: NIST SP 800-73; Yubico yubikey-manager 5.9.1 source files
`yubikit/piv.py`, `ykman/piv.py`, `ykman/_cli/piv.py`. Sources were consulted as
specifications only, not imported or executed by the implementation.
