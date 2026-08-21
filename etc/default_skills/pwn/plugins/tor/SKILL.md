---
name: pwn-plugins-tor
description: Drive PWN::Plugins::Tor from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Tor
  source: pwn/plugins/tor.rb
---

# PWN::Plugins::Tor

This plugin processes images into readable text

## When to use

Call `PWN::Plugins::Tor` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/tor.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Tor.help
PWN::Plugins::Tor.start(opts)
```

## Public methods

- `start`
- `switch_exit_node`
- `stop`
- `authors`
- `help`

## Source

`pwn/plugins/tor.rb`

## Verification

`PWN::Plugins::Tor.respond_to?(:start)` after the
module is loaded. Read the source for parameter names.
