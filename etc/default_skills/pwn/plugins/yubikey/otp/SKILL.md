---
name: pwn-plugins-yubikey-otp
description: Use native OTP slots with explicit consent and readback.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  preserve: true
  module: PWN::Plugins::YubiKey::OTP
  source: pwn/plugins/yubikey/otp.rb
---

# PWN::Plugins::YubiKey::OTP

Native Ruby OTP application commands over the selected `Connection.exchange`
boundary. No executable, subprocess, interpreter or network backend. HID framing
and CRC validation belong to `Transport`; APDU status handling belongs to
`Protocol`. The caller owns its transport connection.

## Operations

`execute(args: [...], connection: ...)` accepts argv **after** `otp`.
`operations` lists ten leaves: `info`, `swap`, `ndef`, `delete`, `yubiotp`,
`static`, `chalresp`, `calculate`, `hotp`, `settings`. Empty args return local
metadata, not a device query. Unknown flags/commands and credential argv raise.

Typed methods: `info`, `swap`, `delete_slot`, `configure_ndef`, `settings`,
`provision_yubiotp`, `provision_static`, `provision_hotp`,
`provision_challenge_response`, `challenge_response`, `calculate`, `help`,
`authors`. Read runtime `help` for the full option contract.

## Safe workflow

1. Select the exact intended device using root transport selectors. Do not scan
   or open real hardware in default tests. A model name does not establish its
   supported/enabled applications.
2. Read `info` without authentication. Firmware/status observations, not guessed
   credentials, gate slot operations. NDEF additionally checks actual NFC support.
3. Require literal `confirm: true` for every write or calculation. `--force` is
   syntactic compatibility, not consent. Never provision to repair a vault-open
   failure, stale response, wrong slot or missing device.
4. Supply secrets as raw in-memory `key:`, `password:`, `private_id:`,
   `access_code:` and `new_access_code:`. An explicit `secret_provider` receives
   a missing secret's Symbol. No implicit terminal reads or factory secrets.
   Generated material requires `secret_sink.call(field, raw_secret)`. The sink is
   caller-controlled and must not log or publish secrets.
5. `challenge_response(connection:, challenge:, slot: 2, confirm: true)` accepts
   **1–64 raw bytes** and returns **20 raw HMAC-SHA1 bytes**. It never hex-encodes,
   truncates to a TOTP or caches a response. Trailing zero challenges use distinct
   padding. USB calculation requires OTP HID; smartcard calculation is NFC-only.
6. `provision_challenge_response` defaults to touch-required and performs a fresh
   native OpenSSL HMAC comparison against device output after programming and
   separate status readback. Its default return is `:verified`; `details: true`
   returns scoped verification metadata. `execute ['chalresp', '2']` returns the
   metadata and follows prior CLI default
   of no touch unless `--touch`. `--totp` explicitly decodes supplied Base32 key
   text in memory; otherwise `key_encoding` defaults to raw. Keys 21–64 bytes
   cannot fit this application; longer HMAC keys are SHA1-shortened per HMAC.
7. Check `verification`, not only `verified`. Other OTP credentials/settings have
   no secret/config export command: their verification is programming sequence
   and slot-state readback, **not proof of keyboard output or secret equality**.
   Known 5.0–5.4.2
   smartcard zero-sequence responses are labeled `firmware_quirk_slot_state`;
   HMAC provisioning must still pass the cryptographic challenge comparison.
   Never claim that state metadata proves an NFC URI's emitted value. Failed or
   stale readback raises an uncertainty error; no write is automatically replayed.

## Formats and device restrictions

- YubiOTP: public ID is lowercase modhex, private ID six raw bytes, AES key sixteen
  raw bytes. `--serial-public-id` reads the actual API serial.
- Static passwords: 1–38 characters; MODHEX, US, UK, DE, FR, IT, BEPO and NORMAN
  scan-code maps. Unsupported characters fail before programming. The map data
  retains Yubico's BSD license in source.
- HOTP: raw HMAC key, 6/8 digits, initial counter divisible by 16 and at most
  1048560; optional modhex/BCD token identifier.
- NDEF: URI prefix compression or UTF8 English text, encoded prefix ≤54 bytes;
  requires a configured slot on an NFC-capable key.
- Settings replace omitted keyboard options with defaults, as the prior command
  did; they do not infer hidden previous settings. Firmware 4.3.2–4.3.5 access-code
  updates are refused without any delete/reprogram fallback.
- Explicit YubiOTP `config_output` appends Yubico CSV only after status readback to
  an owned, mode-0600 regular file with no symlinks/hardlinks and an exclusive
  lock. CSV contains secrets. `--upload` is retired upstream and fails without
  any network call. Generated secrets still require an explicit in-memory sink.

## Evidence and references

Offline specs use fake **connection wire responses**, real shared APDU codecs,
RFC 2202 HMAC and RFC 6238 TOTP vectors, and an independently computed fixed
52-byte configuration/CRC vector. These are not hardware interoperability tests.

Protocol provenance: official yubikey-manager **5.9.1** source (`yubikit/yubiotp.py`,
`yubikit/core/otp.py`, `ykman/scancodes`) and
<https://developers.yubico.com/yubikey-personalization/Manuals/ykpersonalize.1.html>.
Native reference header:
<https://github.com/Yubico/yubikey-personalization/blob/master/ykcore/ykdef.h>.
