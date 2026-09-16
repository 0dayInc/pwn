---
name: pwn-plugins-handler
description: Drive PWN::Plugins::Handler from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Handler
  source: pwn/plugins/handler.rb
---

# PWN::Plugins::Handler

Payload generation and listener sessions without Metasploit.

## When to use

Call `PWN::Plugins::Handler` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/handler.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Handler.help
PWN::Plugins::Handler.required_bins(opts)
```

## Public methods

- `required_bins`
- `generate`
- `listen`
- `accept`
- `interact`
- `stop`
- `authors`
- `help`

## Source

`pwn/plugins/handler.rb`

## Verification

`PWN::Plugins::Handler.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
