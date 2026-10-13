# Installation

PWN ships as a **single Ruby gem** whose runtime is 100 % `autoload`ed -
a plugin whose native extension or OS binary is missing costs nothing until
you actually touch that constant. That means the install is **two steps**:

```bash
gem install --verbose pwn      # 1. get the gem (pure-Ruby core always works)
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
gem install --verbose pwn
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

cron worker                 ok   systemd --user pid=...

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
2. Map those to OS packages for **this** distro and version
   (`PWN::Plugins::DetectOS.distro` / `.version`, e.g. Kali `2026.3` vs Ubuntu
   `24.04`) via `PWN::Setup.packages_for`. Family fallbacks still live in
   `PWN::Setup::NATIVE_GEMS` / `::TOOLCHAIN`. Tools with no OS package on this
   distro (Frida, one_gadget, ROPgadget, checksec, ropper, kube-hunter, or
   Kali-only names on Ubuntu) install via `pipx` (Debian/Kali/Ubuntu) or `pip`
   / `gem`, or are skipped so one missing apt name cannot abort the whole
   profile. Each OS package is installed in its own `apt-get`/`dnf`/… command.
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
| `re` | `Radare2` · `GDB` · `ExploitDev` · `Frida` · Android RE (`apktool`/`jadx`) · `pwndbg` · `ropper` · `rizin` |
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

## Upgrading - `~/.pwn` state migration (`PWN::Migrate`)

PWN persists a growing set of files under `~/.pwn` (encrypted config,
memory, learning, metrics, mistakes, extrospection, cron, agents, skills,
sessions, swarm, curriculum, finetune, ...). Each file is owned by a different
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
   Schema 5 adds `ai.agent.skill_review` (`recommend` when the key is absent).

Everything is idempotent and dry-run capable. The plain `pwn` launcher also
prints a one-line drift warning on startup whenever `~/.pwn/.schema`
predates the running gem (`PWN::Migrate.needed?`).

Schema `v1` also seeds `PWN::Cron.install_defaults` - the nightly
`curriculum_practice` and weekly `curriculum_train` self-improvement jobs
(see [Reinforcement Learning](Reinforcement-Learning.md)). `pwn setup`
also starts the background cron worker and persists it via the OS scheduler
(systemd --user / launchd / schtasks / crontab) so those YAML jobs run
without a per-job crontab line. Live Policy files (`policy.json`,
`policy_traj.jsonl`) are created on first agent turn when `ai.agent.policy`
is on.

Schema `v8` seeds the enabled `session_cleanup` hygiene job, daily at 03:45
in the scheduler's local timezone. First launch also seeds it through
`PWN::Cron.install_defaults`. The bundled `etc/default_cron/session_cleanup.rb`
is installed to `~/.pwn/cron/session_cleanup.rb`; managed copies refresh on
subsequent launches/migrations, while unmarked custom helpers are preserved.
An existing job named `session_cleanup` keeps its ID, schedule, enabled state,
payload and native scheduler drop-ins. New jobs defer cleanup until their first
scheduled time, rather than deleting during initial catch-up.

Cleanup calls a session named only when its persisted metadata has
`title_source: summary`, a nonblank title and summary, and a positive integer
`summary_turns` cursor: the fields published after validated LLM title generation.
Provisional first-request titles, manual titles, persona labels, aliases and
historical embedded titles are not evidence of LLM summarization. Legacy records
without provenance are unsummarized with `missing_summary_provenance`; invalid or
incomplete metadata is unknown, never named. `/sessions list` and cleanup share
`title_source`, `is_summarized`, `classification` and `title_reason`. Classification
does not establish deletion safety: malformed records, symlinks and uncertain pin
stores remain protected. Age alone does not preserve an unsummarized session.
Version 5 backs up unreferenced unsummarized sessions before a guarded `Sessions.delete`
call that bypasses the ordinary age pin. Current sessions and every known
learning/mistake/memory reference remain protected. `/sessions list` exposes
`dependencies` as an array of files **referencing this session** (empty when
none), not files this session depends on. `dependency_errors` lists unknown,
malformed or unsafe stores; cleanup fails closed when it is nonempty.
The shared index follows defined structural fields, not ID-looking text.
Dependency-backed sessions remain visible and resumable, not archived away.
Vault/config/credential payloads and historical backups are not scanned.
Same-user interactive PWN
processes defer deletion because existing writers have no lifetime leases; this is a
conservative guard, not a cross-process session lease. Inspect without deleting:
`ruby ~/.pwn/cron/session_cleanup.rb --dry-run`.

`--apply` backs up eligible transcript/metadata bytes under
`~/.pwn/session_cleanup_archive/<run>/` (directories 0700, files 0600), outside
`/sessions list`. Atomic, fsynced backups are SHA-256 verified before deletion;
file identities/hashes, title classification, reference stores and process state
are rechecked under per-ID/transcript locks. `ledger.json` records exact IDs,
hashes, skips and completed deletions; dry-run JSON contains metadata only and
creates no archive. Backups are for recovery, not an automatic reference
resolver: referenced placeholders remain in the active list until a separately
verified archive-aware lookup policy exists. No memory, learning or mistake
records are rewritten. The process checks and advisory locks do not claim a
transactional guarantee against arbitrary non-cooperating external writers.

The cleanup-specific pins additionally preserve every session ID referenced in
retained learning, mistake and durable memory stores, including non-gold learning
and old resolved mistakes. References are schema-aware:

| Store / writer | Session reference |
| --- | --- |
| `learning.jsonl` / Learning; `policy_traj.jsonl` / Policy; `open_goal.json` / OpenGoal | Top-level `session_id` |
| `mistakes.json` / Mistakes | Each signature record's `sessions[]` and `verified_sessions[]`; signature keys are not session IDs |
| `memory.json`, `memory.archive.json` / Learning.reflect, Memory | Exact `reflect_<session ID>_<8-hex lesson digest>` keys; arbitrary memory keys, values and source strings are not links |
| `jobs/<12-hex job ID>.json` / Jobs | Top-level `session_id`; command, environment and job ID are not links |
| `swarm/*/personas.json` / Swarm | Persona-to-session map values, not persona names or swarm IDs |
| `curriculum/log.jsonl` / Curriculum | `practice` event's `data[].runs[].session_id`; other events' prose is not traversed |
| `extrospection.json` / Extrospection | `auto_extrospect` observations' second tag in `['drift', session ID]`; manual/other tags and observation data are not links |
| `engagements/*/facts.jsonl` / Swarm | Top-level `source_session` |
| `findings.jsonl` / Findings | Top-level `session_id`; exact transcript/sidecar paths in `evidence_paths[]` and `poc_artifacts[]` |
| Engagement evidence and recon ledgers / Findings, Recon | Exact transcript/sidecar paths in `path` or `evidence_path`; includes the legacy root `engagements/evidence.jsonl` |
| `artifacts/manifest.jsonl` / ArtifactRegistry | Top-level `session` and exact transcript/sidecar `source_path`; `kind: swarm-bus` uses `session` for a swarm ID, not session provenance |
| `artifacts/<session ID>/index.jsonl`, `engagement-memory.json` | Session ownership from that exact directory; index `src` may also reference a transcript/sidecar |
| `embeddings/<session ID>.db`, `sessions/<session ID>/trace.jsonl` | Ownership from that exact filename/directory, not database contents or trace tool payloads |

IDs must be complete canonical values, not substrings or whitespace-normalized
tokens. Only known evidence/source path fields pointing directly into the
configured sessions directory are path references. There is currently no
cross-session link field in transcript or title metadata schemas: listing,
recalling, quoting JSON, or mentioning a session never pins it, including when
`sessions_list` output is saved repeatedly. Self listings do not create pins.

The index also validates the JSON containers in policy, preference, sentinel,
skill-review and KPI stores, run checkpoints, mission ledgers, swarm bus/solve
records, curriculum model/cooldown maps, engagement descriptors/hosts/scans and
binary facts. These writers do **not** persist session ownership links; their
arbitrary payloads, prompts, run/job IDs and user-selected labels must not be
interpreted as such. Unknown JSON stores within the indexed directories are
reported as uncertainty rather than silently ignored. Adding a new reference
schema requires auditing its writer/callers and adding positive and negative
fixtures, not a recursive key-name or text search. Vaults, loot payloads, arbitrary
artifact content and backups remain outside this index.

Native scalar tool `step_reward` fields are recognized;
unknown transcript fields remain protected.

`/sessions list` reads all transcript files afresh, not just cleanup candidates.
In cleanup output, `unnamed` includes protected sessions; `candidate_ids` excludes
them. Active sessions hold shared OS locks on permanent per-ID cleanup lock
files; cleanup takes an exclusive nonblocking lock on the same inode before
rechecking, backing up and deleting. An active A does not retain inactive B.
CLI/REPL activation and resume transfer ownership, exit releases it, nested
Loop requests and title writers hold independent leases, and crashes release
descriptors automatically. Stale lock contents or reused PIDs confer no ownership.
Never unlink lock files: that would split the synchronization inode.

Old installed processes cannot be upgraded by refreshing the cron helper alone.
`legacy_owners` reports launchers without the held PID/start-identity capability
marker; `unknown_legacy_ownership` means their in-memory session IDs are unknown,
not that every session is active. Ask the operator to identify/quiesce those
writers and restart using the updated source or deployed version before deleting
ambiguous candidates. Do not infer active IDs from mtimes, titles or process-name
matches, and do not bypass reference/summary guards. No config migration is needed.

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
RUN gem install --verbose pwn && pwn setup --profile full --yes
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
`~/.pwn/pwn.yaml` template. It also seeds bundled skills into
`~/.pwn/skills/` when those names are missing:

- `vulnerability-research-fundamentals`
- `deep-exploitation`
- `bug-bounty-hunting`
- `sast-code-scans`
- `reverse-engineering-binaries`
- `penetration-testing`
- `web-application-penetration-testing`
- `red-teaming`
- `hardware-and-firmware-testing`
- `social-engineering`
- `osint`
- `cwe`
- `capec`
- `att&ck`
- `humanizer`

Source lives in the gem at `etc/default_skills/`. `PWN::Config.install_default_skills`
walks every `SKILL.md` recursively (idempotent SOP copies; never overwrites an
edited SOP `SKILL.md`). Generated module skills under `etc/default_skills/pwn/`
`PWN::` module, plus `references/` when the source has CWE/NIST/URLs) are
copied to `~/.pwn/skills/pwn/` and **are** overwritten on
`pwn setup --migrate` / first launch so they stay in sync with `lib/pwn`.
`bundle exec rake` runs `:module_skills` (`PWN::ModuleSkills.refresh!`)
before spec so `etc/default_skills/pwn` matches live `PWN::` class methods.
`pwn setup --migrate` and `pwn-ai` start copy that tree to `~/.pwn/skills/pwn`. Add at least one
LLM engine key with the `pwn-vault` REPL command to enable `pwn-ai` - see
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
PWN::Migrate::STATE_FILES                 # declarative registry of every ~/.pwn artifact
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
pwn[CURRENT_VERSION]:003 >>> PWN::Plugins.constants.count   # => 67
pwn[CURRENT_VERSION]:004 >>> PWN::SAST.constants.count      # => 48
pwn[CURRENT_VERSION]:005 >>> pwn-ai                         # launches agent TUI
```

**Next:** [Configuration](Configuration.md) · [General Usage](General-PWN-Usage.md) · [Persistence](Persistence.md)

[← Home](Home.md)
