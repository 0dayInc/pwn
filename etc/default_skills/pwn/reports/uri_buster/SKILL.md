---
name: pwn-reports-uribuster
description: Drive PWN::Reports::URIBuster from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::URIBuster
  source: pwn/reports/uri_buster.rb
---

# PWN::Reports::URIBuster

This plugin generates the War Dialing results produced by pwn_www_uri_buster.

## When to use

Call `PWN::Reports::URIBuster` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/uri_buster.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::URIBuster.help
PWN::Reports::URIBuster.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/reports/uri_buster.rb`

## Verification

`PWN::Reports::URIBuster.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
