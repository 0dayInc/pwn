---
name: pwn-redaction
description: Drive PWN::Redaction from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  preserve: true
  module: PWN::Redaction
  source: pwn/redaction.rb
---

# PWN::Redaction

Write-boundary redaction; reject cyclic or over-100-level containers before inspecting secrets. `redact` never opens a credential store; `capture` can explicitly store ordinary secret matches.

## When to use

Call `PWN::Redaction` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/redaction.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

PINs, PUKs, MFA/OTP values, access codes, management keys, OATH secrets, static
passwords and SCP key fields use the constant `[REDACTED]` mask in hashes and
key-value text. Do not replace those masks with hash markers: low-entropy values
can be brute-forced from unsalted digests. `capture` masks these fields without
storing them. Ordinary API/password tokens retain the existing digest behavior.

For other captured loot, pass `yubikey: {slot: 2, serial: '12345678', timeout: 30}`
to select hardware encryption. Hardware capture failure must leave the returned
text redacted and must never trigger software fallback. A returned capture
reference is not proof of successful persistence; verify metadata separately.

```ruby
PWN::Redaction.help
PWN::Redaction.redact(opts)
```

## Public methods

- `redact`
- `token`
- `capture`
- `authors`
- `help`

## Source

`pwn/redaction.rb`

## Verification

`PWN::Redaction.respond_to?(:redact)` after the
module is loaded. Read the source for parameter names.
