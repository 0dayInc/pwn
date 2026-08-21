---
name: pwn-plugins-jsonpathify
description: Drive PWN::Plugins::JSONPathify from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::JSONPathify
  source: pwn/plugins/json_pathify.rb
---

# PWN::Plugins::JSONPathify

This plugin is for leveraging XPath-like searching capabilities for JSON data structures

## When to use

Call `PWN::Plugins::JSONPathify` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/json_pathify.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::JSONPathify.help
PWN::Plugins::JSONPathify.search_key(opts)
```

## Public methods

- `search_key`
- `authors`
- `help`

## Source

`pwn/plugins/json_pathify.rb`

## Verification

`PWN::Plugins::JSONPathify.respond_to?(:search_key)` after the
module is loaded. Read the source for parameter names.
