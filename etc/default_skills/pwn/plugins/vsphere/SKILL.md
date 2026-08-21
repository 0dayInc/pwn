---
name: pwn-plugins-vsphere
description: Drive PWN::Plugins::Vsphere from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Vsphere
  source: pwn/plugins/vsphere.rb
---

# PWN::Plugins::Vsphere

This plugin is used for interacting w/ VMware ESXI's REST API

## When to use

Call `PWN::Plugins::Vsphere` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/vsphere.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Vsphere.help
PWN::Plugins::Vsphere.login(opts)
```

## Public methods

- `login`
- `logout`
- `authors`
- `help`

## Source

`pwn/plugins/vsphere.rb`

## Verification

`PWN::Plugins::Vsphere.respond_to?(:login)` after the
module is loaded. Read the source for parameter names.
