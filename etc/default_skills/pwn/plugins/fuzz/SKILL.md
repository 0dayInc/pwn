---
name: pwn-plugins-fuzz
description: Drive PWN::Plugins::Fuzz from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Fuzz
  source: pwn/plugins/fuzz.rb
---

# PWN::Plugins::Fuzz

This plugin was created to support fuzzing various networking protocols. A request template with fuzz delimiters is combined with a payload and optional layered encodings, then replayed over TCP/UDP (optionally TLS).

## When to use

Call `PWN::Plugins::Fuzz` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/fuzz.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Fuzz.help
PWN::Plugins::Fuzz.socket(opts)
```

## Public methods

- `socket`
- `authors`
- `help`

## Source

`pwn/plugins/fuzz.rb`

## Verification

`PWN::Plugins::Fuzz.respond_to?(:socket)` after the
module is loaded. Read the source for parameter names.
