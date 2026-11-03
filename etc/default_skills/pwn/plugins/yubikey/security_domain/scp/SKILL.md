---
name: pwn-plugins-yubikey-security-domain-scp
description: Use the native SCP03 and SCP11 APDU channel wrapper.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  preserve: true
  module: PWN::Plugins::YubiKey::SecurityDomain::SCP
  source: pwn/plugins/yubikey/security_domain/scp.rb
---

# SCP channel implementation

Prefer `SecurityDomain.secure_connection` to direct `SCP.open`. Both require
explicit keys and literal confirmation; see the parent SecurityDomain skill
for in-memory key and certificate options. Public-key pins and certificates are
explicit trust decisions: do not discover a card key and silently pin it. Pass
unencrypted PEM/DER or already-decrypted OpenSSL key objects; this module never
prompts a terminal for encrypted-PEM passwords. This module never discovers devices
or spawns executables. Returned APDU wrappers retain verified status words,
serialize counter/MAC updates and invalidate themselves after any uncertain
exchange or authentication failure. Do not reuse an underlying connection after
handshake failure, and never replace a failed channel with plaintext I/O.

SCP03 supports YubiKey S8/AES128: derives S-ENC/S-MAC/S-RMAC, verifies the full
card cryptogram, authenticates the host at security level 0x33, uses CBC with
counter-derived IVs and ISO7816 padding, and verifies R-MAC before decryption.
SCP11a/b/c use native OpenSSL EC agreement, SHA256 X9.63 KDF and receipt CMAC;
certificate trust is explicit, not silently bypassed. CA validation is offline
and does not retrieve CRLs/OCSP. No guaranteed memory erasure is claimed.

The descriptor advertises `extended_apdu: true`. The shared Protocol layer must
honor this before command chaining: upstream SCP wraps the whole command before
transport fragmentation, not each plaintext chunk. The wrapper accepts short and
extended input and upgrades encrypted payloads over 255 bytes to extended frames.
Transport `61xx` fragments are collected with raw GET RESPONSE before one R-MAC
verification, preserving the counter/MAC chain. This is continuation retrieval,
never authentication failure fallback. Fragment count, total response size and
elapsed time are bounded. Noncanonical receipt encodings and padding longer than
one AES block fail closed.

References: GlobalPlatform Card Specification 2.3 Amendments D/F; official
Yubico yubikit 5.9.1 core/smartcard/scp.py and smartcard/__init__.py. Tests use
RFC 4493 known vectors and independent synthetic card-side cryptographic
transcripts, not implementation-produced fixture outputs or real secrets.
