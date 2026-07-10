# Contributing

## Repo layout

```text
lib/pwn/                # all namespaces
lib/pwn/setup.rb        # PWN::Setup — doctor/provisioner data tables
lib/pwn/plugins/        # 66 plugin modules
lib/pwn/ai/agent/       # agent core
lib/pwn/ai/agent/tools/ # LLM tool registrations
bin/                    # 53 pwn_* drivers (incl. pwn_setup)
spec/                   # RSpec (incl. conventions_spec)
documentation/          # this wiki + diagrams
```

## Conventions (enforced by `spec/conventions_spec.rb`)

1. Every public module method is `public_class_method def self.name(opts = {})`.
2. Every arg-accepting `def self.*` uses **exactly** `(opts = {})` — no
   positional args, no keyword args.
3. Every module has `self.help` returning a usage string.
4. `# frozen_string_literal: true` at the top of every `.rb`.

## Quality gates

```bash
rake            # rubocop + rspec — must be zero offenses
```

(`rvmsudo rake` on multi-user RVM installs.)

## Adding a plugin

1. `lib/pwn/plugins/my_thing.rb` following the conventions above.
2. Autoload entry in `lib/pwn/plugins.rb`.
3. `spec/lib/pwn/plugins/my_thing_spec.rb`.
4. Optional `bin/pwn_my_thing` driver (see [Drivers](Drivers.md)).
5. Optional agent tool in `lib/pwn/ai/agent/tools/` (see
   [Agent Tool Registry](Agent-Tool-Registry.md)).
6. **If it needs a native gem or external binary**, add **one row** to
   `PWN::Setup::NATIVE_GEMS` or `PWN::Setup::TOOLCHAIN` in
   `lib/pwn/setup.rb` (with `apt:`/`dnf:`/`pacman:`/`brew:`/`port:` package
   names + the `plugins:` it unlocks) and, if it belongs in a capability
   set, reference it from `PWN::Setup::PROFILES`. That single edit makes
   `pwn setup` install it on every OS and every install path (gem, git,
   Docker, Packer, Vagrant, CI). **Do not** add a new bash provisioner.
7. Update [Plugins.md](Plugins.md) and, if it changes a data flow, the
   relevant `.dot` in `documentation/diagrams/dot/` → `./build.sh`.

## Commit / release

`./git_commit.sh` bumps `PWN::VERSION`, regenerates
`third_party/pwn_rdoc.jsonl`, runs the gates, and pushes.

[← Home](Home.md)
