---
name: pwn-jsontext
description: Drive PWN::JSONText from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::JSONText
  source: pwn/json_text.rb
---

# PWN::JSONText

Retag or scrub strings before the JSON generator sees them.

## When to use

Call `PWN::JSONText` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/json_text.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::JSONText.help
PWN::JSONText.prepare(opts)
```

## Public methods

- `prepare`
- `authors`
- `help`

## Source

`pwn/json_text.rb`

## Verification

`PWN::JSONText.respond_to?(:prepare)` after the
module is loaded. Read the source for parameter names.
