---
name: pwn-sast-factory
description: Drive PWN::SAST::Factory from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Factory
  source: pwn/sast/factory.rb
---

# PWN::SAST::Factory

SAST Module used to identify if source may result in exposing the application to XXE vulnerabilities. For more information see: https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing

## When to use

Call `PWN::SAST::Factory` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/factory.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Factory.help
PWN::SAST::Factory.scan(opts)
```

## Public methods

- `scan`
- `security_references`
- `authors`
- `help`

## References

- `references/security.md` — CWE / NIST mapping
- `references/urls.md` — URLs from source

## Source

`pwn/sast/factory.rb`

## Verification

`PWN::SAST::Factory.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
