---
name: pwn-migrate
description: Drive PWN::Migrate from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Migrate
  source: pwn/migrate.rb
---

# PWN::Migrate

PWN::Migrate — the ~/.pwn state **doctor** and **auto-migrator**. PWN persists a growing set of files under `~/.pwn` (encrypted config, memory, learning outcomes, metrics, mistakes, extrospection, cron jobs, agents, skills, sessions, swarm buses, …). Each file is owned by a different module and each release can add keys or change shape. A user upgrading `gem install pwn` between two versions could therefore hit `KeyError`, `NoMethodError for nil`, or a silent empty-fallback because their on-disk state predates the new loader. `PWN::Migrate` closes that gap. It is called from: * `pwn setup --migrate` — explicit doctor + autofix * `PWN::Setup.check` — read-only ~/.pwn state section * `PWN::Config.refresh_env` — one-line drift warning on every launch It works by: 1. Stamping `~/.pwn/.schema` with `{ schema:, pwn_version:, at: }` the first time it runs. Any release that changes the on-disk shape of a `~/.pwn` file bumps `SCHEMA_VERSION` here and appends an idempotent lambda to `MIGRATIONS`. 2. Declaratively verifying every state file against its OWNING module's own loader (`STATE_FILES`) — no re-implemented parsers. If the raw file has bytes but the owner returned its empty-fallback, the file is flagged incompatible. 3. Autofixing: timestamped backup → ordered schema migrations → per-file repair (quarantine corrupt / re-seed missing) → `pwn.yaml` deep-key backfill (missing keys from the current `PWN::Config.env_template` are merged in-place under the user's values, then the vault is re-encrypted with the SAME key/iv). Everything is idempotent, dry-run capable, and never overwrites a user-set value.

## When to use

Call `PWN::Migrate` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/migrate.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Migrate.help
PWN::Migrate.installed_schema(opts)
```

## Public methods

- `installed_schema`
- `needed`
- `status`
- `check`
- `run`
- `vault_drift`
- `backfill_vault`
- `env_template`
- `authors`
- `help`

## Source

`pwn/migrate.rb`

## Verification

`PWN::Migrate.respond_to?(:installed_schema)` after the
module is loaded. Read the source for parameter names.
