---
name: pwn-plugins-yubikey-management
description: Configure native device capabilities with exact readback.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  preserve: true
  module: PWN::Plugins::YubiKey::Management
  source: pwn/plugins/yubikey/management.rb
---

# PWN::Plugins::YubiKey::Management

Native device information/configuration over OTP HID, management smartcard or
CTAP vendor commands. No executable, subprocess, interpreter or network backend.

## API and routing

`execute(args: [...], connection: ...)` takes argv after `config`.
`operations` lists five prior leaves: `usb`, `nfc`, `mode`, `set-lock-code`, `reset`.
Empty args return local metadata without device I/O. `--force` is not consent.
Typed APIs: `info`, `configure_usb`, `configure_nfc`, `set_mode`, `set_lock_code`,
`reset`, `reboot`, `help`, `authors`. See runtime help for exact options.

## Procedure

1. Select the exact device explicitly. `info` reads version, serial, transport
   capability masks, lock state, flags/timeouts, NFC restrictions, FIPS masks and
   reset metadata. Retain unknown raw TLVs; reject malformed/duplicate records and
   bound pagination. Do not infer all apps from a model or firmware version.
2. On pre-4.1 firmware, report unavailable capability metadata explicitly and
   only expose observed USB product/interface information. On 4.x, do not trust
   the broken USB-enabled tag; 4.2.4 has a documented supported-mask correction.
3. Application toggles and lock configuration require firmware 5.x plus observed
   capabilities. `--enable`/`--disable` may repeat. Unsupported apps, conflicting
   options, disabling all USB apps and missing lock metadata fail before a write.
   `--list` is read-only and cannot be combined with changes.
4. Every write/reboot/reset requires literal `confirm: true`. Lock material is
   sixteen raw in-memory bytes via `lock_code:`/`new_lock_code:` or an explicit
   `secret_provider.call(field)`. Never guess a credential. Generation requires
   `secret_sink.call(:new_lock_code, bytes)`; never print the generated value.
5. Write once, then read actual device information and compare requested fields.
   Any lost acknowledgment, mismatching readback or identity change raises an
   uncertainty error; never automatically resend. A lock flag verifies protection
   state, not export/equality of the lock secret.
6. USB interface changes normally reboot and need an explicit `reconnect`
   callable before writing. It receives nonsecret prior identity metadata and
   must return a fresh handle to the exact device. The returned handle is closed
   after readback; the original connection remains caller-owned. Never rediscover
   or switch to the first available key. Serial-less reconnection must preserve
   the same observed explicit selector; missing/changed selectors fail uncertain.
   Use `reboot: false` only to intentionally
   defer activation; stored configuration readback is not active-interface proof.
7. Legacy NEO/4 `mode` emits the four-byte little-endian mode/timeouts record.
   Reconnect after physical reinsertion and verify the observed USB product ID
   maps to exactly the requested interfaces. A CCID reader that provides no USB
   product ID cannot prove full legacy interface mode; fail uncertain rather than
   claim success. Legacy timeout values are not readable and are labeled so.
8. Full-device reset is gated by Bio multi-protocol/PIV or reset-blocked capability
   metadata and smartcard transport, not assumed available on all YubiKeys. Verify
   the fresh reset-state field is cleared. `data_erasure_verified: false` is
   explicit: configuration metadata does not independently prove forensic erasure
   of every application credential. Use application-specific resets otherwise.
9. NFC restriction is available from firmware 5.7 and lasts until USB power.
   Disabling the currently used NFC path needs a separately usable readback path;
   absence or lost connectivity is uncertainty, never verified completion.

## Evidence boundaries

Same-path specs use synthetic HID/APDU/CTAP wire frames and the real shared
Protocol codec. They cover field packing, pagination, mutations/readback,
capability/version refusals, secrets, stale responses and legacy modes. No real
hardware, credential, network service or global reset is exercised by default.
Physical compatibility across firmware/models still requires explicit operator
hardware validation.

Protocol provenance: official yubikey-manager **5.9.1** source,
`yubikit/management.py`, `yubikit/core/otp.py`, `ykman/_cli/config.py` and
<https://docs.yubico.com/yesdk/yubikey-api/Yubico.YubiKey.Management.Commands.html>.
