---
name: pwn-runtimefingerprint
description: Drive PWN::RuntimeFingerprint from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::RuntimeFingerprint
  source: pwn/runtime_fingerprint.rb
---

# PWN::RuntimeFingerprint

Read-only deployment diagnostics. A disk observation at compilation is not an attestation of VM bytecode, native extensions, or later monkey patches.

## When to use

Call `PWN::RuntimeFingerprint` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/runtime_fingerprint.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::RuntimeFingerprint.help
PWN::RuntimeFingerprint.report(opts)
```

## Public methods

- `report`
- `authors`
- `help`

## Source

`pwn/runtime_fingerprint.rb`

## Verification

`PWN::RuntimeFingerprint.respond_to?(:report)` after the
module is loaded. Read the source for parameter names.
