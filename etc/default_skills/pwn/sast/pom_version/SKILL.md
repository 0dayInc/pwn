---
name: pwn-sast-pomversion
description: Drive PWN::SAST::PomVersion from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::PomVersion
  source: pwn/sast/pom_version.rb
---

# PWN::SAST::PomVersion

SAST Module used to identify the versions of dependent software within source repos to ensure patching requirements for those dependencies can be met.

## When to use

Call `PWN::SAST::PomVersion` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/pom_version.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::PomVersion.help
PWN::SAST::PomVersion.scan(opts)
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

`pwn/sast/pom_version.rb`

## Verification

`PWN::SAST::PomVersion.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
