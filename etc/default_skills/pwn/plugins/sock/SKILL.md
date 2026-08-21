---
name: pwn-plugins-sock
description: Drive PWN::Plugins::Sock from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Sock
  source: pwn/plugins/sock.rb
---

# PWN::Plugins::Sock

This plugin was created to support fuzzing various networking protocols

## When to use

Call `PWN::Plugins::Sock` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/sock.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Sock.help
PWN::Plugins::Sock.connect(opts)
```

## Public methods

- `connect`
- `get_random_unused_port`
- `check_port_in_use`
- `listen`
- `get_tls_cert`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/plugins/sock.rb`

## Verification

`PWN::Plugins::Sock.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
