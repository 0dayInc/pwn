---
name: pwn-plugins-yubikey-transport
description: Use native HIDAPI and PC/SC YubiKey transports.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  preserve: true
  module: PWN::Plugins::YubiKey::Transport
  source: pwn/plugins/yubikey/transport.rb
---

# Native YubiKey transport

## Procedure

1. `Transport.available?(application: :piv)` probes **host shared libraries only**.
   Optional `backend: :hid` or `:pcsc` narrows the probe. Requiring the module and
   checking availability never initialize HIDAPI, enumerate devices, establish a
   PC/SC context, or open hardware. Availability does not prove permission,
   service health, card presence, or application support.
2. `Transport.devices(timeout: 5)` explicitly enumerates HID interfaces and
   PC/SC readers. Reader descriptors do not prove that a card is inserted.
   `backend:`, exact `serial:`, `reader:` and `device_path:` filter inventory.
   This inventory call does not connect to cards to obtain their serials.
3. `Transport.open(application: :otp, serial: '0007', timeout: 30)` selects one
   endpoint or raises on absent/ambiguous selection. Preserve the operator's
   exact serial String; never normalize, trim or parse it as an Integer.
   Use `device_path:` or `reader:` for serial-less Security Key models. A reader
   explicitly selects PC/SC, including OTP/management smartcard variants. Generic
   NFC readers require explicit selection. Default OTP/FIDO prefers matching HID;
   other applications prefer PC/SC. PC/SC ownership is exclusive, with no shared
   fallback, process killing, automatic authentication or command replay.
4. Call `connection.exchange(opts)` and always close in `ensure`. The descriptor's
   `:protocol` is authoritative:
   - `:otp`: `command:` byte, binary `data:` up to 64 bytes, optional
     `response_length:`. CRC is checked and removed; status writes require a
     programming-sequence acknowledgment. Command `0` with empty data reads six
     status bytes without writing a command. Supply expected data lengths whenever
     known; variable-length replies require an unambiguous CRC/padding boundary.
   - `:ctap`: `command:` in 1..127, excluding internal INIT/CANCEL/KEEPALIVE/ERROR,
     binary `data:` up to 7609 bytes. `open` performs nonce-checked CTAPHID INIT and
     exposes `:version` and `:capabilities`. Responses retain the CTAP status byte.
   - `:apdu`: binary `data:` containing the complete C-APDU. The result is the
     complete R-APDU **including SW1/SW2**; shared `Protocol.apdu` owns chaining,
     GET RESPONSE and application-status validation.
5. `timeout:` is a finite positive monotonic budget. Optional `cancelled:` is a
   callable returning truthy to stop; `on_keepalive:` receives 1 (processing) or
   2 (touch/user presence). Callbacks must be bounded and thread-safe. They run
   on the connection's owner worker. Never log packet bodies or secret replies.

## Lifecycle and limits

- A transport error, interrupted exchange or deadline retires the connection.
  CTAPHID CANCEL / OTP reset is sent serially after the current native call.
  Application-error status bytes are returned unchanged and do not retire it.
  Do not expect subsequent application cleanup on a retired connection to work.
- `close` is idempotent. `:closed` means native cleanup completed; `:closing`
  means it is deferred. Timed-out C calls retain their owned thread, buffers and
  handle until the native call returns. Never kill that Ruby thread or close its
  in-flight handle: this would risk a use-after-free and is not native cancellation.
- HID interrupt reads use `hid_read_timeout`. HID feature/write calls and PC/SC
  `SCardTransmit` have no portable hard deadline. `SCardCancel` does not universally
  cancel transmit. A permanently stuck driver may retain a thread and native
  resources indefinitely; a bounded Ruby waiter is not driver-independent abort.
- Explicit serial selection may perform read-only OTP identity APDUs, with a
  management-information fallback using shared Protocol codecs when OTP is
  disabled. Unobservable identities fail closed; no serial is invented.
- PC/SC `:transport` derives from the Yubico ATR USB/NFC distinction; it is not
  cryptographic device/vendor attestation. HID transport is USB. NEO's historic
  cached-programming-sequence workaround is not issued automatically; uncertain
  acknowledgments fail rather than trigger an implicit write or retry.

## Offline verification

Run `bundle exec rspec spec/lib/pwn/plugins/yubikey/transport_spec.rb` and focused
RuboCop on the paired source/spec. Default tests use fake native C-library/IO
boundaries with independent fixed CTAPHID and OTP CRC/framing fixtures. They
exercise ordering, bounds, exact selectors, platform ABI widths/wide strings,
blocked-call ownership, cancellation, and native cleanup without real hardware.
Linux library-symbol load checks are separate from physical interoperability;
Windows/macOS ABI simulations are not tests executed on those operating systems.

## Protocol provenance

This is a native Ruby implementation, not a launcher or a vendored SDK runtime.
Protocol references:

- YubiKey Manager 5.9.1 `yubikit/core/otp.py`, `yubikit/yubiotp.py`, and
  `ykman/pcsc/__init__.py` (read-only reference).
- python-fido2 2.2.1 `fido2/hid/__init__.py` (read-only reference), and the
  [FIDO HID protocol](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#usb-hid).
- [HIDAPI 0.14.0 C header](https://github.com/libusb/hidapi/blob/hidapi-0.14.0/hidapi/hidapi.h).
- [PC/SC ABI definitions](https://github.com/LudovicRousseau/PCSC/blob/master/src/PCSC/wintypes.h):
  Unix `DWORD=unsigned long`, Darwin `DWORD=uint32`, Windows handles pointer-sized;
  exported PCI symbols avoid guessed structure packing.
- [Microsoft SCardCancel](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardcancel)
  and [SCardTransmit](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardtransmit).
