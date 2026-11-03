---
name: pwn-plugins-yubikey-protocol
description: Native binary framing for YubiKey device protocols.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  preserve: true
  module: PWN::Plugins::YubiKey::Protocol
  source: pwn/plugins/yubikey/protocol.rb
---

# Native YubiKey protocol framing

Use the shared native Ruby codec rather than reconstructing binary headers in
callers. Preserve raw bytes, repeated TLV tags and exact identifiers. Reject
truncated/oversized frames before issuing device operations. This module does not
run an executable or discover hardware merely when loaded.

See `PWN::Plugins::YubiKey::Protocol.help` for the current public codec surface.
Offline framing regressions are in `spec/lib/pwn/plugins/yubikey/protocol_spec.rb`.
