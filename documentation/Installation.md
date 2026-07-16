# Installation

PWN ships as a **single Ruby gem** whose runtime is 100 % `autoload`ed -
a plugin whose native extension or OS binary is missing costs nothing until
you actually touch that constant. That means the install is **two steps**:

```bash
gem install pwn      # 1. get the gem (pure-Ruby core always works)
pwn setup            # 2. doctor + provision this host's capabilities
```

`pwn setup` is the built-in **doctor / provisioner** (`PWN::Setup`). It
detects your OS package manager (`apt` · `dnf` · `pacman` · `brew` · `port`),
reports which `PWN::` capabilities are usable on *this* host, and - when
asked - installs exactly the OS headers, external tools, and native gems
needed to unlock the ones you want. No `/opt/pwn` checkout, no `rvmsudo`
chain, no bash provisioners required.

Tested on **Kali / Debian / Ubuntu**, **Fedora**, **Arch**, and **macOS**
(Homebrew or MacPorts). Ruby ≥ 3.3 (RVM, rbenv, asdf, or system Ruby).

---

## Quick install (recommended)

```bash
gem install pwn
pwn setup                      # read-only doctor: what's usable, what's missing
pwn setup --profile full --yes # install everything for every PWN:: namespace
pwn                            # launch the REPL
```

```text
pwn[CURRENT_VERSION]:001 >>> PWN.help
```

If you only need a subset (e.g. web testing on a CI runner, SDR on a lab
box), install just that **capability profile** - see below.

---

## `pwn setup` - the post-install doctor & provisioner

Three equivalent spellings ship with the gem:

| Invocation | Same as |
|---|---|
| `pwn setup [opts]` | bare-word subcommand of `bin/pwn` |
| `pwn_setup [opts]` | standalone driver (`bin/pwn_setup`) |
| `pwn --setup[=PROFILE]` | flag form; no `PROFILE` = check, `PROFILE` = deps |

### Read-only doctor (default)

```bash
$ pwn setup            # or: pwn setup --check   / pwn --setup / pwn_setup
```

Prints a per-capability report and **exits non-zero if anything is degraded**
(so you can gate CI on it):

```text
PWN vCURRENT_VERSION · ruby 4.0.5 · linux x86_64 · pkg-manager: apt

~/.pwn/                    ok   (13 entries · schema v1)
~/.pwn/pwn.yaml            ok   (encrypted, decryptor present)
AI engine                  ok   anthropic (key set)

Ruby extensions
  pg             MISSING  (needs: postgresql-server-dev-all)  → PWN::Plugins::DAOPostgres
  pcaprub        ok                                            → PWN::Plugins::Packet, extro_packet
  nokogiri       ok                                            → PWN::Plugins::TransparentBrowser, PWN::WWW
  ...

External toolchain                              used by
  nmap           ok    /usr/bin/nmap            PWN::Plugins::NmapIt
  gqrx           MISSING                        PWN::SDR, extro_rf_tune
  ...

~/.pwn state files                              owner
  pwn.yaml       ok                             PWN::Config
  memory.json    ok                             PWN::Memory
  skills/        drift  1 legacy flat file(s)   PWN::Config     → run --migrate --fix
  ...

31 / 36 capabilities usable · 5 degraded

Run `pwn setup --deps` to install missing OS headers/tools, or
    `pwn setup --profile <name>` for a subset. See `pwn setup --list-profiles`.
```

### Install dependencies

```bash
pwn setup --deps                     # profile :full - everything
pwn setup --profile web              # just TransparentBrowser · Burp · ZAP · Tor
pwn setup --profile sdr --yes        # non-interactive (CI / packer / docker)
pwn setup --profile net --dry-run    # print the apt/dnf/brew/... commands only
pwn setup --list-profiles
```

`--deps` / `--profile` will:

1. Resolve the profile → set of native gems + external binaries.
2. Map those to OS packages for **your** package manager (data lives in
   `PWN::Setup::NATIVE_GEMS` / `::TOOLCHAIN` - versioned with the gem, so
   `gem install pwn`, git checkout, Docker, Packer and Vagrant all read the
   same table).
3. Show the exact commands, prompt (unless `--yes`), run them, then
   `gem pristine` / `gem install` any native extension that still fails to
   load, and re-run the doctor.

### Capability profiles

`pwn setup --list-profiles` (source of truth: `PWN::Setup::PROFILES`)

| Profile | Unlocks |
|---|---|
| `core` | `~/.pwn` bootstrap · vault · REPL - always applied |
| `ai` | verify at least one AI engine key/oauth in `~/.pwn/pwn.yaml` |
| `web` | `TransparentBrowser` · `BurpSuite` · `Zaproxy` · `extro_verify` · `extro_watch` · `sqlmap` · `tor` |
| `net` | `NmapIt` · `Packet` · `extro_packet` · `extro_osint` · `tshark`/`tcpdump` |
| `db` | `DAOPostgres` · `DAOSQLite3` · `DAOMongo` |
| `sdr` | `PWN::SDR` · GQRX · `PWN::FFI` DSP backends · `extro_rf_tune` · rtl-sdr / hackrf / SoapySDR |
| `vision` | `OCR` · `ScannableCodes` · `Reports` · `extro_vision` · tesseract / zbar / graphviz |
| `voice` | `PWN::Plugins::Voice` · `extro_voice` · espeak-ng / sox |
| `exploit` | `Metasploit` · `sqlmap` |
| `hardware` | `Serial` · `BusPirate` · `Android` · `BareSIP` · `extro_serial` · `extro_telecomm` |
| `full` | everything above |

### All flags

```text
pwn setup [--check] [--deps] [--profile NAME] [--list-profiles]
          [--migrate [--fix]] [--yes] [--dry-run]
```

| Flag | Meaning |
|---|---|
| *(none)* / `-c`, `--check` | Read-only doctor. Exit 1 if any capability degraded. |
| `-d`, `--deps` | Install OS packages + rebuild native gems for `--profile` (default `full`). |
| `-p`, `--profile NAME` | One of the profiles above. Implies `--deps`. |
| `-l`, `--list-profiles` | Print profile table and exit. |
| **`-m`, `--migrate`** | **Verify every `~/.pwn` state file against this pwn version; apply schema migrations. See below.** |
| **`-f`, `--fix`** | **With `--migrate`: also autofix incompatible files (timestamped backup taken first).** |
| `-y`, `--yes` | Assume yes; non-interactive (CI / Docker / Packer). Also implies `--fix` when combined with `--migrate`. |
| `-n`, `--dry-run` | Print the commands that *would* run, do nothing. |

---

## Upgrading — `~/.pwn` state migration (`PWN::Migrate`)

PWN persists a growing set of files under `~/.pwn` (encrypted config,
memory, learning, metrics, mistakes, extrospection, cron, agents, skills,
sessions, swarm, curriculum, finetune, …). Each file is owned by a different
module and each release can add keys or change shape. `PWN::Migrate` closes
that gap so `gem update pwn` never leaves you with a `KeyError` or a silent
empty-fallback.

```bash
gem update pwn
pwn setup --migrate            # verify + apply schema migrations (backup taken)
pwn setup --migrate --fix      # also autofix incompatible files
pwn setup --migrate --dry-run  # report only, write nothing
```

What `--migrate` does:

1. **Stamp** `~/.pwn/.schema` with `{ schema:, pwn_version:, at: }`. Any
   release that changes the on-disk shape of a `~/.pwn` file bumps
   `PWN::Migrate::SCHEMA_VERSION` and appends an idempotent lambda to
   `PWN::Migrate::MIGRATIONS`.
2. **Verify** every state file against its owning module's *own* loader
   (`PWN::Migrate::STATE_FILES` - no re-implemented parsers). If the raw
   file has bytes but the owner returned its empty-fallback, the file is
   flagged incompatible.
3. **Autofix** (with `--fix`): timestamped backup under `~/.pwn/backup/<ts>/`
   → ordered schema migrations → per-file repair (quarantine corrupt to
   `~/.pwn/quarantine/`, re-seed missing dirs, strip unparsable JSONL lines,
   convert legacy flat skills to the [agentskills.io](https://agentskills.io)
   directory layout) → **deep-merge** any keys the current
   `PWN::Config.env_template` added into your encrypted `~/.pwn/pwn.yaml`
   **without overwriting your values** (re-encrypted with the same key/IV).

Everything is idempotent and dry-run capable. The plain `pwn` launcher also
prints a one-line drift warning on startup whenever `~/.pwn/.schema`
predates the running gem (`PWN::Migrate.needed?`).

Schema `v1` also seeds `PWN::Cron.install_defaults` — the nightly
`curriculum_practice` and weekly `curriculum_train` self-improvement jobs
(see [Reinforcement Learning](Reinforcement-Learning.md)).

From a checkout:

```bash
cd /opt/pwn && git pull && rake install && pwn setup --migrate --fix
```

---

## From a git checkout (contributors)

```bash
git clone https://github.com/0dayinc/pwn /opt/pwn
cd /opt/pwn
bundle install
rake install                         # or: rvmsudo rake install (multi-user RVM)
pwn setup --profile full --yes       # same provisioner, same data tables
```

The legacy `./install.sh` / `packer/provisioners/pwn.sh` bash paths still
work, but they now simply delegate to `pwn setup` - the `case $os` package
lists have been consolidated into `PWN::Setup::NATIVE_GEMS` / `::TOOLCHAIN`.

---

## Docker / Packer / Vagrant / CI

`pwn setup` is the single provisioning entry point for every image builder:

```dockerfile
FROM kalilinux/kali-rolling
RUN gem install pwn && pwn setup --profile full --yes
```

```yaml
# .gitlab-ci.yml - fail the job if the runner is missing a capability
before_script:
  - pwn setup --profile web --yes
  - pwn setup --check
```

```bash
# packer / vagrant provisioner
pwn setup --profile ${PWN_PROFILE:-full} --yes
```

---

## First-run configuration

The first `pwn` launch creates `~/.pwn/` and an **encrypted**
`~/.pwn/pwn.yaml` template. Add at least one LLM engine key with the
`pwn-vault` REPL command to enable `pwn-ai` - see
[Configuration](Configuration.md). `pwn setup` will report the AI-engine
row as `MISSING` until a key is set.

---

## Programmatic API - `PWN::Setup` / `PWN::Migrate`

Everything above is a thin CLI over two autoloaded modules:

```ruby
PWN::Setup.check                          # → { ok:, native_gems_missing:, toolchain_missing:, state:, pkg_manager:, os:, arch: }
PWN::Setup.deps(profile: :web, yes: true) # install, then re-check
PWN::Setup.list_profiles
PWN::Setup.migrate(fix: true)             # thin wrapper → PWN::Migrate.run
PWN::Setup.pkg_manager                    # → { key: :apt, install: 'sudo apt-get install -y', sudo: true }

# The data tables - single source of truth, versioned with the gem:
PWN::Setup::NATIVE_GEMS   # native ext  → { apt:, dnf:, pacman:, brew:, port:, plugins: }
PWN::Setup::TOOLCHAIN     # external bin → { apt:, dnf:, pacman:, brew:, port:, plugins: }
PWN::Setup::PROFILES      # profile      → { desc:, gems:, bins: }

# ~/.pwn state doctor / auto-migrator (lib/pwn/migrate.rb)
PWN::Migrate.needed?                      # cheap: schema stamp < SCHEMA_VERSION ?
PWN::Migrate.status                       # per-file compatibility rows (never writes)
PWN::Migrate.check                        # human report + { compatible:[], incompatible:[], missing:[] }
PWN::Migrate.run(fix: true, dry_run:false)# backup → ordered migrations → per-file repair → vault backfill
PWN::Migrate.vault_drift                  # keys env_template has that your pwn.yaml is missing
PWN::Migrate.backfill_vault               # deep-merge those keys under your values, re-encrypt
PWN::Migrate::STATE_FILES                 # declarative registry of every ~/.pwn artefact
PWN::Migrate::SCHEMA_VERSION              # bump when a state file changes shape
```

Adding a new native dependency or wrapped binary? Add **one row** to the
appropriate constant in `lib/pwn/setup.rb`. Adding a new persisted state
file under `~/.pwn`? Add **one entry** to `PWN::Migrate::STATE_FILES` in
`lib/pwn/migrate.rb` - every install path (gem, git, Docker, Packer,
Vagrant, CI) picks it up automatically.

---

## Verify

```ruby
pwn[CURRENT_VERSION]:001 >>> PWN::Setup.check[:ok]          # => true
pwn[CURRENT_VERSION]:002 >>> PWN::Migrate.needed?           # => false
pwn[CURRENT_VERSION]:003 >>> PWN::Plugins.constants.count   # => 66
pwn[CURRENT_VERSION]:004 >>> PWN::SAST.constants.count      # => 48
pwn[CURRENT_VERSION]:005 >>> pwn-ai                         # launches agent TUI
```

**Next:** [Configuration](Configuration.md) · [General Usage](General-PWN-Usage.md) · [Persistence](Persistence.md)

[← Home](Home.md)
