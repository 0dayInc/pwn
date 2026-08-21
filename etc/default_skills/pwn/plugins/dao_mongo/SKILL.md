---
name: pwn-plugins-daomongo
description: Drive PWN::Plugins::DAOMongo from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::DAOMongo
  source: pwn/plugins/dao_mongo.rb
---

# PWN::Plugins::DAOMongo

This plugin needs additional development, however, its intent is to be used as a data access object for interacting w/ MongoDB

## When to use

Call `PWN::Plugins::DAOMongo` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/dao_mongo.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::DAOMongo.help
PWN::Plugins::DAOMongo.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/plugins/dao_mongo.rb`

## Verification

`PWN::Plugins::DAOMongo.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
