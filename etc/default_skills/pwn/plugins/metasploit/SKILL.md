---
name: pwn-plugins-metasploit
description: Drive PWN::Plugins::Metasploit from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Metasploit
  source: pwn/plugins/metasploit.rb
---

# PWN::Plugins::Metasploit

Plugin used to integrate Metasploit into PWN leveraging a listening MSFRPCD daemon.

## When to use

Call `PWN::Plugins::Metasploit` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/metasploit.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Metasploit.help
PWN::Plugins::Metasploit.connect(opts)
```

## Public methods

- `connect`
- `console_exec`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/plugins/metasploit.rb`

## Verification

`PWN::Plugins::Metasploit.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
