---
name: pwn-sast-beefhook
description: Drive PWN::SAST::BeefHook from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::BeefHook
  source: pwn/sast/beef_hook.rb
---

# PWN::SAST::BeefHook

SAST Module used to detect if the default BeEF exploitation hooks reside within source code.

## When to use

Call `PWN::SAST::BeefHook` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/beef_hook.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::BeefHook.help
PWN::SAST::BeefHook.scan(opts)
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

`pwn/sast/beef_hook.rb`

## Verification

`PWN::SAST::BeefHook.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
