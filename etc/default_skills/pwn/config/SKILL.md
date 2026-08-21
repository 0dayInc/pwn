---
name: pwn-config
description: Drive PWN::Config from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Config
  source: pwn/config.rb
---

# PWN::Config

Used to manage PWN configuration settings within PWN drivers.

## When to use

Call `PWN::Config` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/config.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Config.help
PWN::Config.env_template(opts)
```

## Public methods

- `env_template`
- `default_env`
- `redact_sensitive_artifacts`
- `init_driver_options`
- `refresh_env`
- `pwn_skills_path`
- `sanitize_skill_name`
- `parse_skill_frontmatter`
- `parse_skill_references`
- `write_skill`
- `migrate_legacy_skills`
- `default_skill_names`
- `default_skills_dir`
- `install_default_skills`
- `load_skills`
- `pwn_memory_path`
- `load_memory`
- `pwn_sessions_path`
- `pwn_cron_path`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/config.rb`

## Verification

`PWN::Config.respond_to?(:env_template)` after the
module is loaded. Read the source for parameter names.
