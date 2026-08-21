---
name: pwn-sast-typescripttypejuggling
description: Drive PWN::SAST::TypeScriptTypeJuggling from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::TypeScriptTypeJuggling
  source: pwn/sast/type_script_type_juggling.rb
---

# PWN::SAST::TypeScriptTypeJuggling

SAST Module used to identify loose comparisons (i.e. == instead of ===) within TypeScript source code.

## When to use

Call `PWN::SAST::TypeScriptTypeJuggling` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/type_script_type_juggling.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::TypeScriptTypeJuggling.help
PWN::SAST::TypeScriptTypeJuggling.scan(opts)
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

`pwn/sast/type_script_type_juggling.rb`

## Verification

`PWN::SAST::TypeScriptTypeJuggling.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
