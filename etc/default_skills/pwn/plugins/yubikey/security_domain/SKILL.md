---
name: pwn-plugins-yubikey-security-domain
description: Manage native YubiKey Security Domain keys and channels.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  preserve: true
  module: PWN::Plugins::YubiKey::SecurityDomain
  source: pwn/plugins/yubikey/security_domain.rb
---

# Native Security Domain

Use `operations`, `help`, `execute(args: ..., connection: ...)` and
`secure_connection(connection: ..., scp: ..., kvn: ..., confirm: true)`.
Key and certificate values stay in Ruby/OpenSSL memory, never command-line
arguments, environment variables, logs or subprocesses. No factory keys are
assumed. Never print key objects, raw APDUs, or key-bearing options.

## Secure connection

- SCP03: explicit 16-byte `key_enc`, `key_mac`, optional `key_dek` binary Strings.
- SCP11a/b/c: explicit `card_public_key` EC pin, or trusted `ca_certificates`
  Array of X509 objects/PEM/DER; `card_certificates` is optional leaf-last chain.
  With only CA anchors, fetch the card bundle and verify it before authentication.
- SCP11a/c additionally require `oce_private_key` and leaf-last `oce_certificates`;
  optional `oce_kid` and `oce_kvn` identify the card's OCE CA key.
- Every handshake requires literal `confirm: true`. The returned connection
  provides `exchange(protocol: :apdu, data:, timeout:)`, `descriptor`, `close`.
- Receipt/card cryptogram failure, malformed response, bad R-MAC, uncertain I/O,
  or exhausted counter closes the channel. No plaintext retry or fallback.
- SCP11b authenticates the card only. SCP11c does not grant SD administrative
  privilege. Use SCP03 or SCP11a for SD writes.

## Administrative operations

`execute` implements `info`, `reset`, `keys generate`, `keys import`,
`keys export`, `keys delete`, `keys set-allowlist`, `keys set-certificate`,
and `keys set-ca-issuer`. Group paths only return local help metadata.

Pass KID/KVN as exact unsigned decimal or `0x` hexadecimal argv tokens. Imports
and generation require KVN 1..127. KID 1 imports the complete SCP03 keyset from
`key_enc`, `key_mac`, `key_dek`; KID 0x11/0x13/0x15 imports an EC `key`;
KID 0x10/0x20..0x2f imports an EC public `key` or CA `certificate`.
All key wrapping uses the authenticated session DEK. KCV verification is mandatory.
Private-key imports may include a matching leaf-last `certificates` bundle;
`ski` sets an explicit CA issuer identifier, and CA certificate SKI is extracted
when available. These are multiple card writes, not an atomic transaction;
do not retry automatically after any failure.

`keys generate` and `keys export` return PEM bytes rather than writing files.
An optional trailing `-` is only a compatibility marker. Export never extracts
private keys. Use `certificates:` and `ski:` for certificate/issuer storage;
allowlist serials may be argv integers or the `serials:` Array. Mutations require
`confirm: true` and a genuine SCP03/SCP11a wrapper. `--force` is not consent.
Reset is deliberately plaintext-only, follows the documented bounded key-blocking
sequence, and reads back the default-key state before reporting success.

Curves are prime256v1, secp384r1, secp521r1, brainpoolP256r1,
brainpoolP384r1 and brainpoolP512r1. P-521 private-key import is explicitly
unsupported because its 66-byte scalar is not block-aligned for the pinned SDK's
un-padded CBC PUT KEY encoding; key generation and public-key handling work.
All actual card curve/capacity support remains firmware-dependent.

## Evidence boundary

Wire behavior is based on GlobalPlatform Card Specification 2.3 Amendments D
(SCP03 S8/AES128) and F v1.4 (SCP11), and Yubico's official yubikit 5.9.1
`securitydomain.py` and `core/smartcard/scp.py`. These are references, not runtime
dependencies. NIST SP 800-38B/RFC 4493 vectors and independent synthetic APDU
peers validate the host cryptography offline; no physical device compatibility
is claimed. No SCP03 S16, key diversification, CRL/OCSP retrieval, or guaranteed
Ruby/OpenSSL memory zeroization is provided. Unauthenticated post-handshake
status-only replies fail closed rather than releasing an unverified status.
