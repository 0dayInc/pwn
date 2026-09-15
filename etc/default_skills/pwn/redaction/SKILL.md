---
name: pwn-redaction
description: Drive PWN::Redaction from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Redaction
  source: pwn/redaction.rb
---

# PWN::Redaction

Shared write-boundary redaction. Never opens a credential store.

## When to use

Call `PWN::Redaction` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/redaction.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

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
