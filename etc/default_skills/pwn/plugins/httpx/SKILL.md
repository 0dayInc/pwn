---
name: pwn-plugins-httpx
description: Drive PWN::Plugins::Httpx from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Httpx
  source: pwn/plugins/httpx.rb
---

# PWN::Plugins::Httpx

httpx JSONL probe: live URLs, status, title, and detected tech stack.

## When to use

Call `PWN::Plugins::Httpx` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/httpx.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Httpx.help
PWN::Plugins::Httpx.required_bins(opts)
```

## Public methods

- `required_bins`
- `probe`
- `techs`
- `authors`
- `help`

## Source

`pwn/plugins/httpx.rb`

## Verification

`PWN::Plugins::Httpx.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
