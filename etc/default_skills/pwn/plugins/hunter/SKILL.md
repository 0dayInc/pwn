---
name: pwn-plugins-hunter
description: Drive PWN::Plugins::Hunter from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Hunter
  source: pwn/plugins/hunter.rb
---

# PWN::Plugins::Hunter

This plugin is used for interacting w/ Hunter's REST API using the 'rest' browser type of PWN::Plugins::TransparentBrowser. This is based on the following Hunter API Specification: https://hunter.how/search-api

## When to use

Call `PWN::Plugins::Hunter` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/hunter.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Hunter.help
PWN::Plugins::Hunter.search(opts)
```

## Public methods

- `search`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/hunter.rb`

## Verification

`PWN::Plugins::Hunter.respond_to?(:search)` after the
module is loaded. Read the source for parameter names.
