---
name: pwn-plugins-irc
description: Drive PWN::Plugins::IRC from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::IRC
  source: pwn/plugins/irc.rb
---

# PWN::Plugins::IRC

This plugin was created to interact with IRC protocols

## When to use

Call `PWN::Plugins::IRC` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/irc.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::IRC.help
PWN::Plugins::IRC.connect(opts)
```

## Public methods

- `connect`
- `join`
- `names`
- `privmsg`
- `ping`
- `pong`
- `part`
- `quit`
- `listen`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/plugins/irc.rb`

## Verification

`PWN::Plugins::IRC.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
