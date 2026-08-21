---
name: pwn-plugins-urischeme
description: Drive PWN::Plugins::URIScheme from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::URIScheme
  source: pwn/plugins/uri_scheme.rb
---

# PWN::Plugins::URIScheme

This plugin provides useful credit card capabilities

## When to use

Call `PWN::Plugins::URIScheme` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/uri_scheme.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::URIScheme.help
PWN::Plugins::URIScheme.list_all_known(opts)
```

## Public methods

- `list_all_known`
- `authors`
- `help`

## Source

`pwn/plugins/uri_scheme.rb`

## Verification

`PWN::Plugins::URIScheme.respond_to?(:list_all_known)` after the
module is loaded. Read the source for parameter names.
