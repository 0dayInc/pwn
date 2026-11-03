---
name: pwn-plugins-yubikey-oath
description: Use native OATH with exact account identities.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  preserve: true
  module: PWN::Plugins::YubiKey::OATH
  source: pwn/plugins/yubikey/oath.rb
---

# Native OATH

## When to use

Use `PWN::Plugins::YubiKey::OATH` for OATH application APDUs, not software-only OTP
or browser WebAuthn. The root YubiKey router owns transport lifetime.

## Public API

- `execute(args:, connection:, ...)` implements `info`, `reset`, `access change`,
  `remember`, `forget`, and `accounts add`, `uri`, `import`, `list`, `code`,
  `rename`, `delete`. Empty/group args return local metadata.
- `operations`, `help`, `authors` are local metadata.
- `code(connection:, account:, confirm: true, ...)` returns one numeric String.
- `calculate(connection:, account:, challenge:, confirm: true, ...)` returns a
  raw full HMAC, not a formatted OTP.
- `calculate_all(connection:, timestamp:, confirm: true, ...)` returns credential
  records with `code` value/validity Hashes; HOTP and touch records have nil codes.
- `parse_uri(uri:)` validates and parses an in-memory otpauth URI locally.

## Procedure

1. Use a caller-selected APDU connection. Never select the first device implicitly.
2. Pass the exact complete ID returned by LIST, including period/issuer prefixes,
   whitespace and UTF-8 bytes. No substring, case folding or Unicode normalization
   is performed when identifying an account.
3. Use `code` for one numeric OTP String; leading zeroes are significant. Optional
   `timestamp:` is nonnegative Integer epoch seconds. TOTP periods come from the
   credential ID, while HOTP uses an empty challenge and increments its counter.
4. Supply `password:` or sixteen raw bytes in `access_key:` in memory, or an
   explicit `secret_provider:` callback. Authentication is single-attempt with
   mutual HMAC-SHA1 verification after SELECT. Missing or wrong credentials never
   trigger default guesses, repair, cached-key deletion, fallback or retry.
5. For account creation supply `secret:` (raw bytes) or strict `secret_base32:`;
   `--generate` returns the generated seed in memory. Metadata options include
   oath-type, algorithm (SHA1/SHA256/SHA512), digits (6–8), period, issuer, initial
   HOTP counter and touch. Invalid values fail before authentication. Existing
   IDs require explicit `overwrite: true` or `--force` in addition to consent.
6. URI input goes in `uri:`, not argv. Conflicting issuer fields, noncanonical
   Base32, duplicate URI parameters and invalid periods are rejected, not repaired.
7. Bulk import accepts `credentials:` (complete Hash records) or `pskc:` (in-memory
   PSKC 1.0 XML). Validate the complete batch before any authentication/write;
   never silently skip a bad entry. Each successful PUT is checked with LIST.
   Partial device failure is not rolled back or retried.
8. Use `access change` with `new_password:` / `new_access_key:`, or `--clear`.
   Changes read back protection state only, not secret contents. Reset uses DEAD
   confirmation bytes and verifies regenerated salt, unlocked state and empty
   inventory. Rename/delete verify exact IDs and never delete as a repair step.

## Explicit encrypted-cache handoff

There is no built-in host cache or implicit lookup. `access remember`, `--remember`
and `use_cache: true` require an explicit `encrypted_cache:` adapter supplied by
the caller. It must expose `encrypted? == true` and these methods:

```ruby
cache.store(device_id: id, access_key: raw_key)
cache.fetch(device_id: id) # raw bytes or nil
cache.delete(device_id: id)
# access forget --all additionally requires:
cache.clear
cache.empty?
```

The adapter owns encryption-at-rest and unlock policy; the assertion is the
caller's contract, not a cryptographic audit by this module. This is a transfer to
an explicit encrypted storage API, **not a plaintext file store**. Mutations are
read back through the adapter. Stored keys are never deleted after failed auth,
or automatically removed on password change/reset; explicitly forget stale
records. `use_cache:` never falls back to a password after failure. Do not supply
a plaintext Hash/file adapter in production.

## Pitfalls and limits

- `confirm: true` is mandatory for auth, code calculation, mutations and cache
  writes. `--force` does not supply confirmation. Unprotected inventory is read-only.
- Native PSKC import supports plain values, AES-128/192/256 key-wrap and
  MAC-authenticated AES-CBC, raw `pskc_key:` or embedded PBKDF2 with
  `pskc_password:`. Unsupported algorithms, XML signatures and DTD/entities are
  rejected. PSKC export-on-add, legacy file-path argv, arbitrary XML encryption
  algorithms and Steam-specific five-character output are not implemented.
- LIST returns all exact IDs, including hidden-named records. Display-only legacy
  flags do not change the structured result. Exact numeric MFA does not silently
  switch to Steam formatting.
- Touch requires version 4.2.6, SHA512 4.3.1, rename 5.3.1. Known pre-4.3.5 prefix
  overwrite defects fail closed. FIPS policy is ultimately enforced by the
  selected application; no host override or plaintext secure-channel fallback exists.
- No CLI, subprocess, corrupt-account repair, silent credential deletion or disk
  access exists. Ruby does not guarantee memory zeroization.
- A successful APDU or inventory readback is not physical interoperability or
  proof of the imported secret. Timeouts leave mutation state uncertain.

## Verification

Run `bundle exec rspec spec/lib/pwn/plugins/yubikey/oath_spec.rb` and scoped
RuboCop. Tests exercise production Protocol framing and a raw exchange boundary,
including application-specific A5 SEND REMAINING, mutual auth, RFC 6238 vectors,
strict identities, mutation readback, cache handoff, and authenticated PSKC import.
No real hardware, home credentials or network is accessed.

References: Yubico YKOATH protocol and pinned yubikey-manager 5.9.1
`yubikit/oath.py` / `ykman/_cli/oath.py`; RFC 4226, RFC 6238, RFC 6030 and RFC 3394.
https://developers.yubico.com/OATH/YKOATH_Protocol.html
