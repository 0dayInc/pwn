---
name: pwn-plugins-yubikey-hsmauth
description: Manage native HSM Auth credentials and sessions.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  preserve: true
  module: PWN::Plugins::YubiKey::HSMAuth
  source: pwn/plugins/yubikey/hsmauth.rb
---

# Native YubiHSM Auth

## When to use

Use `PWN::Plugins::YubiKey::HSMAuth` for YubiKey YubiHSM Auth credentials and
session-key derivation. This is not the YubiHSM2 management protocol or a browser
WebAuthn ceremony. The root YubiKey router owns transport lifetime.

## Public API

- `execute(args:, connection:, ...)` handles `info`, `reset`, `credentials list`,
  `generate`, `import`, `export`, `symmetric`, `derive`, `delete`, `change-password`,
  and `access change-management-key` / `change-management-password`.
- `operations`, `help`, `authors` are local metadata.
- `open_session(connection:, timeout:)` selects once and returns a session handle.
- `challenge(session:, label:, algorithm:, credential_password:, confirm: true)`
  returns the host challenge or ephemeral uncompressed P-256 public point.
- `calculate(session:, label:, algorithm:, context:, credential_password:,
  card_crypto:, public_key:, confirm: true)` returns a Hash containing exactly
  `key_senc`, `key_smac`, `key_srmac`, each sixteen raw bytes.

## Procedure

1. Select the intended APDU connection; never guess a device or factory key.
2. Read `.help`. Supply passwords/keys only in memory or through a
   `secret_provider:` receiving a field Symbol after literal `confirm: true`.
   Wrong authentication is attempted once; APDU errors preserve `status` without
   logging payloads. Status 63Cx encodes remaining attempts in its low nibble.
3. Use exact complete label bytes. Management changes do not substring-match.
4. Symmetric import uses raw `key_enc:` and `key_mac:` (sixteen bytes each).
   `derive` uses `derivation_password:` with PBKDF2-HMAC-SHA256, salt `Yubico`,
   10,000 iterations. `generate` creates a P-256 private key on device; symmetric
   `--generate` returns the generated keys in memory for explicit caller storage.
5. Asymmetric import accepts `private_key:` as a raw 32-byte scalar, an in-memory
   PEM/DER String or private OpenSSL EC object on prime256v1. Encrypted PEM/DER
   takes `key_password:`; it never prompts implicitly or retries decryption.
   Export returns public key bytes in `RAW`, `PEM` (default) or `DER` format;
   filenames and secret argv are not accepted by the family API.
6. For a live HSM challenge exchange, retain the same `open_session` handle for
   `challenge` and `calculate`. Do not select another application between them.
   Symmetric context is host challenge + card challenge (sixteen bytes), optional
   card cryptogram eight bytes. Asymmetric context is two uncompressed P-256
   points (130 bytes), `public_key:` is the HSM long-term public point, and
   `card_crypto:` contains sixteen bytes. The caller manages the HSM side.
7. Check the returned verification scope. Create/delete/reset verify inventory
   metadata, not private key contents. Password and management-key writes return
   `status: :acknowledged, verification: :not_readable`; no second authentication
   attempt is made merely to simulate readback.

## Pitfalls

- No shell, executable, network lookup, hidden cache or filesystem credential
  lookup is performed. Raw keys are not auto-decoded from hexadecimal Strings.
- Credential/management passwords are at most sixteen raw bytes and zero-padded
  per protocol. An explicitly supplied empty String is allowed, but nil never
  means the factory credential. Ruby memory is not guaranteed zeroizable.
- Asymmetric operations and challenges require application version 5.6.0;
  credential-password changes require 5.8.0. Random management-key generation is
  rejected on 5.8 or later. SELECT failure is not permission to fall back.
- Device timeout, cancellation or failure must propagate; never replay a mutation.
- Session keys are secret return values. Do not print or put them in transcripts.

## Verification

Run `bundle exec rspec spec/lib/pwn/plugins/yubikey/hsmauth_spec.rb` and scoped
RuboCop. The specs exercise production Protocol APDUs with a fake raw exchange
boundary and independent PBKDF2 / P-256 wire vectors. No hardware interoperability
or secure-channel transport is claimed by these offline tests.

References: pinned yubikey-manager 5.9.1 `yubikit/hsmauth.py` and
`ykman/_cli/hsmauth.py`; https://developers.yubico.com/yubihsm-auth/ .
