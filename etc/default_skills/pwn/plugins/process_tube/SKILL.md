---
name: pwn-plugins-processtube
description: Drive PWN::Plugins::ProcessTube from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::ProcessTube
  source: pwn/plugins/process_tube.rb
---

# PWN::Plugins::ProcessTube

PTY.spawn tube: sendline/recvuntil/recvline, persisted across pwn_eval.

## When to use

Call `PWN::Plugins::ProcessTube` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/process_tube.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::ProcessTube.help
PWN::Plugins::ProcessTube.required_bins(opts)
```

## Public methods

- `required_bins`
- `spawn`
- `connect`
- `write_line`
- `recvuntil`
- `recvline`
- `close`
- `authors`
- `help`

## Source

`pwn/plugins/process_tube.rb`

## Verification

`PWN::Plugins::ProcessTube.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
