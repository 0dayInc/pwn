---
name: pwn-sast-deserialjava
description: Drive PWN::SAST::DeserialJava from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::DeserialJava
  source: pwn/sast/deserial_java.rb
---

# PWN::SAST::DeserialJava

SAST Module used to identify if source may result in exposing the Java application to deserialization vulnerabilities. For more information see: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

## When to use

Call `PWN::SAST::DeserialJava` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/deserial_java.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::DeserialJava.help
PWN::SAST::DeserialJava.scan(opts)
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

`pwn/sast/deserial_java.rb`

## Verification

`PWN::SAST::DeserialJava.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
