---
name: pwn-moduleskills
description: Drive PWN::ModuleSkills from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::ModuleSkills
  source: pwn/module_skills.rb
---

# PWN::ModuleSkills

Generate and install one skill per PWN module, mirroring the constant path under etc/default_skills/pwn (e.g. PWN::Plugins::TransparentBrowser → pwn/plugins/transparent_browser/SKILL.md). refresh! rewrites the gem tree when a module changes. install overwrites the operator copy so `pwn setup --migrate` stays current.

## When to use

Call `PWN::ModuleSkills` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/module_skills.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::ModuleSkills.help
PWN::ModuleSkills.enumerate(opts)
```

## Public methods

- `enumerate`
- `relpath`
- `render`
- `refresh`
- `install`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/module_skills.rb`

## Verification

`PWN::ModuleSkills.respond_to?(:enumerate)` after the
module is loaded. Read the source for parameter names.
