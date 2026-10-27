# Installation

## Housekeeping deployment and diagnostics

The packaged `etc/default_cron/session_cleanup.rb` is the shared implementation
for `/maintenance run`, `/maintenance dry-run`, `/sessions cleanup`, and the
managed `session_cleanup` cron job. `/maintenance status` reports physical file
counts, bytes, configured retention, budgets, incomplete scans and safe error
classes. These are storage counts, not the session menu's pagination count.
Curses executes maintenance on its existing command worker, not its render/input
thread. Ctrl+C requests a safe boundary; committed work is not rolled back.

Upgrade the installed gem, run `pwn setup --migrate --fix`, then restart PWN
clients **and the existing cron worker**. Source-checkout edits alone do not
update installed endpoints. Schema 11 seeds a version-1 housekeeping policy and
refreshes the managed helper. Existing job IDs, schedules, disabled states,
custom Ruby payloads, custom unmarked helpers and policy edits are preserved.
A custom helper is not automatically upgraded. Fresh setup is idempotent and
registration never runs cleanup; the default job retains its next-slot guard.
Startup performs fixed-path checks and coalesces a daily background request in
`maintenance/background.json`. The existing cron worker consumes it through the
existing enabled job, never through a second worker. Disabled jobs stay disabled.
Do not apply maintenance while old untracked clients are running: unknown
legacy ownership blocks mutation rather than guessing which sessions are active.

Storage is organized into logical categories without relocating literal evidence
anchors:

| Category | Existing/new locations under `~/.pwn` | Retention contract |
|---|---|---|
| sessions | `sessions/` including support and requests | Eligible unsummarized, inactive, unreferenced transcripts only; physical deletion with backups |
| learning | `learning.jsonl`, `learning/`, `memory*.json`, `mistakes.json`, policy/curriculum/extrospection stores, finetune and preference records | Evidence migration retains exact verified snapshots; unknown records remain protected |
| artifacts | `artifacts/`, `exports/`, `findings.jsonl`, engagements, corpora and binary workspaces | Durable evidence, not disposable cache |
| state | `swarm/`, `cron/`, `agents.yml`, `jobs/`, `missions/`, `runs/`, metrics | Preserve continuation associations and active work |
| logs | `logs/` | Only explicitly registered disposable closed logs are eligible; unknown logs remain |
| cache | `cache/` | Only producer-registered, checksum-verified, inactive disposable files |
| tmp | `tmp/` | Same registration contract; never glob-delete arbitrary temp files |
| maintenance | `maintenance/`, legacy `session_cleanup_archive/` | Policy, permanent locks, metadata ledgers and recoverable quarantine |

`maintenance/policy.json` is non-secret JSON, version 1. `batch_size` defaults to
100; `scan_limit` to 100000. Cooperative admission defaults to `work_items: 100000`,
`work_seconds: 30` and `work_bytes: 67108864` for dependency and maintenance
payload reads, plus reserved disposable backup writes. Existing policy
files acquire these defaults in memory, without rewriting operator values.
`maintenance/layout.json` upgrades recognized inventory v1 to v2 separately from
policy; unknown inventory versions are refused. `retention_days` defaults to sessions 0, logs 30,
cache 7, tmp 1, maintenance 90. Null disables that category's expiry. Session
age is an additional floor, never an override of leases, provenance or evidence.
Learning/artifacts/state remain non-expiring: their policy slots are descriptive,
not authorization to erase evidence. `budget_bytes` enforces pressure eviction
for verified inactive disposable files (logs 256 MiB, cache 512 MiB, tmp 256 MiB,
maintenance 1 GiB), including before ordinary expiry. Null retention still
disables deletion. Budgets never evict protected evidence. Over-budget protected storage needs
operator review, not automatic deletion. Inventory scans are bounded and report
incompleteness rather than claiming a complete total. `bytes` counts logical file
bytes; `unique_bytes` counts each inode once per category. Directory discovery is
streamed for inventory and dependency trees. Work/time admission is cooperative
between phases and items, not a hard deadline: an admitted read, hash or atomic
commit completes. Exhausted/partial dependency indexes block deletion and report
`incomplete`/`interrupted`. Retrying recomputes dependencies; no timeout kills a writer.
Disposable cleanup reserves the complete payload transaction before its first
hash: one bounded read for preview, or five payload-size passes for verification,
backup read/write, backup verification and final source verification on apply.
Reads reject size changes and cannot follow unlimited concurrent growth. Quarantine,
legacy-backup inventory/compaction, atomic-temp recovery and transaction-status
reads also use byte admission. Policy/cursor metadata and durable ledger writes
are control overhead, not a hard total-filesystem-I/O quota; directory name
discovery is not a payload-byte allowance. An oversized item is retained, with
the overall maintenance run marked `incomplete`/`interrupted`; raise the explicit
work budget to process it. Once admitted, backup/commit finishes even if the
deadline expires mid-write.

Producer integration uses `PWN::SessionCleanup.register_disposable(path:,
category:, expires_at:)` after closing a reproducible file. Producers must hold
its permanent `<path>.lease` exclusively while writing, and readers hold it
shared throughout use. The registry records exact SHA-256, inode and byte count.
Changed, unknown, symlinked, active and invalid files are retained with reasons.
Disposable scans persist a lexical round-robin cursor in
`maintenance/disposable.cursor`; `scan_limit` bounds inspected manifests per run.
Completed/missing manifests remain for audit, including normal temporary-producer
unlinks, but cannot monopolize later scans. Active/changed entries are revisited
on the next circuit. The cursor is scheduling state only: cleanup never removes
or relocates registry entries, and rechecks registration bytes under the producer
lease so a concurrent renewal cannot authorize deletion using an old expiry.
Dry-run does not advance the cursor. A partial circuit reports `incomplete`.
Registration is not permission to classify evidence as disposable. Legacy caches
and logs are not implicitly registered. Transcript compaction/append instead use
a permanent transcript `.write.lock`; compaction temporary files are unique,
cleaned in ensure, fsynced and atomically replaced. Corrupt transcripts raise,
not silently compact into partial transcripts.

Ghidra decompile and BinaryParser triage now publish and read their canonical
caches under permanent leases. Ordinary `Log.append` diagnostics now go to
`logs/pwn.log`, rotating at 1,024,000 bytes into registered closed segments.
Debug streams hold a lifetime lease and register after request closure; active
streams cannot be evicted. Historical `/tmp/pwn.log` and learning logs are not
implicitly deleted. Cache writes and transcript compaction clean their own
temporary outputs on failure rather than leaving routine temp garbage.

Routine disposable cleanup writes exact private backups and prepared/committed
ledgers under `maintenance/quarantine/`. Only verified committed disposable
backups expire after the maintenance retention period or under budget pressure.
Interrupted `expiry_prepared` operations resume from verified remaining backups.
Broad operations also have prepared/committed/interrupted metadata ledgers under
`maintenance/runs/`, exposed by status. Prepared/corrupt ledgers
and unique evidence are never expired. `prune_legacy_backups` recognizes actual
committed session snapshots, dependency-removal backups, learning migration and
continuation-retirement ledgers. After retention or under maintenance pressure it
reclaims **redundant physical bytes** using checksum/readback-verified atomic
hardlink replacement. Recovery filenames remain intact; the last copy is never
removed. Unknown/uncommitted records are excluded. A cross-filesystem link failure
retains the original. Prepared/committed compaction journals are resumable.

`PWN::SessionCleanup.recovery_status(ledger: absolute_ledger_path)` identifies
supported actions. `recover(ledger:, action:, dry_run: true)` is explicit:
- `restore`: quarantine or legacy session copies, with no overwrite of different bytes;
- `rollback`: Learning's validated rollback or an unchanged continuation retirement;
- `rollback_dependencies`: exact targeted store rollback, after restoring source sessions;
- `resume`: re-evaluate broad maintenance, resume backup compaction, or re-evaluate
  offline layout migration (apply requires `writers_stopped: true`).
Use `dry_run: false` only after reviewing the plan. Restoring a metadata ledger
never undoes data changes. Broad operations have independently committed children,
not a fictitious all-or-nothing rollback. Unknown schemas require manual review.
`reorganize` remains explicit and offline; this upgrade does not move existing paths.

### Housekeeping acceptance ledger (isolated fixtures)

`spec/lib/pwn/session_cleanup_recovery_spec.rb` exercises the actual maintenance
entry point, without live stores or providers:

| Requirement | Regression evidence | Boundary |
|---|---|---|
| Byte admission precedes disposable payload I/O | Expired 1 MiB cache with `work_bytes: 1024` remains intact; no payload read/hash or backup, run incomplete/interrupted | Cooperative allowance, not a hard filesystem-I/O cap |
| Repeated bounded scans progress | `scan_limit: 1`, two expired caches and a normally unlinked temporary producer; repeated runs delete both caches and retain all manifests | Registry pathname discovery still enumerates names; inspection is bounded |
| Active/mutated data remains protected | Held shared lease and changed payload survive while later eligible data is processed; released lease is revisited | Requires cooperating permanent producer leases |
| Re-registration is not lost | Renewing the same file between discovery and lease acquisition retains it; republished cache survives a later cursor circuit | Cursor never moves/deletes registry records |
| Admitted commit finishes safely | Deadline expires after backup publication; exact backup and committed child deletion survive, enclosing run is interrupted | Not all-or-nothing rollback |
| Related quarantine reads respect admission | Expired 1 MiB backup exceeds an 8 KiB work allowance and remains committed/unexpired | Legacy/atomic paths also admit reads; their existing integrity/recovery regressions remain enabled |

The completed isolated-HOME `bundle exec rake` gate passed 4,568 examples with
zero failures and inspected 1,161 files with no RuboCop offenses (exit 0).
Cancellation regressions distinguish preservation before deletion admission from
completion of an already-admitted commit; redaction covers the canonical log and
debug/progress/mirror/stderr/fallback sinks. These are fixture-based verification,
not live deployment acceptance: no live-store maintenance, installed-helper
deployment or provider run is implied.

### Temporary producer ownership audit

The audit covers `Dir.tmpdir`, `Tempfile`, `mktmpdir` and atomic replacement
call sites, not a filesystem filename sweep:
- Festival speech input now uses `SessionCleanup.temporary` in `~/.pwn/tmp`, with
  a lifetime lease and exact registration. Concurrent calls have unique names;
  normal completion unlinks the input and a crashed consumer leaves registered bytes.
- Ghidra/BinaryParser canonical cache publication and managed temporary inputs
  journal atomic ownership (inode/device, expected hash, exact target) under
  `maintenance/atomic`. `recover_atomic_temps` rejects active writers, changed or
  partial bytes, missing journals and unknown paths. Routine maintenance applies
  retention; explicit recovery can inspect an abandoned journal immediately.
- Sandbox/Detonate, GPS, RFID, OSINT bridge and GhidraHeadless work directories,
  GDB stdin, and policy-evaluation/Solve verification trees are scoped block or
  owner-cleaned resources. Old unregistered crash remnants are retained, not
  inferred disposable from a prefix. GhidraHeadless's legacy/custom cache is not
  silently enrolled as a canonical cache.
- Nmap/Nuclei scan output, proxy HAR, browser screenshots, APK output, Workspace
  downloads, history spill and Burp diagnostics may be unique evidence. Their
  existing literal paths remain; no age-based global `/tmp` cleanup is authorized.
- OAuth/vault/selection, learning/session/map and SDR image atomic outputs may be
  only-copy state or evidence. Their own ensure/rollback protocols remain; unknown
  remnants are not automatically discarded. Solve lock inodes are permanent.
This is an intentional ownership/evidence boundary, not a claim that every plugin
scratch file is automatically reclaimable.

Swarm registry retirement alone deliberately keeps its saved conversation.
The command route exposes `/swarm retire NAME --continuation` explicitly.
`PWN::AI::Agent::Swarm.retire(name:, swarm_id:, local: true, continuation: true)`
explicitly retires the inactive association with a backup and prepared/committed
ledger. It does not itself delete the transcript. A later persona request creates
a new session; active associations cannot be retired. Persona map writers and
cleanup share a permanent continuation lock.

Safe checks: `/maintenance status` and `/maintenance dry-run` do not call a
provider. Do not use `run` as a diagnostic on production data without reviewing
the preview. Permission and disk failures retain recoverable bytes and report
error classes; no blanket root-directory chmod is attempted.


PWN ships as a **single Ruby gem** whose runtime is 100 % `autoload`ed -
a plugin whose native extension or OS binary is missing costs nothing until
you actually touch that constant. That means the install is **two steps**:

```bash
gem install --verbose pwn      # 1. install the gem and its Ruby/native dependencies
pwn setup            # 2. doctor + provision this host's capabilities
```

`pwn setup` is the built-in **doctor / provisioner** (`PWN::Setup`). It
detects your OS package manager (`apt` · `dnf` · `pacman` · `brew` · `port`),
reports which `PWN::` capabilities are usable on *this* host, and - when
asked - installs exactly the OS headers, external tools, and native gems
needed to unlock the ones you want. No `/opt/pwn` checkout, no `rvmsudo`
chain, no bash provisioners required.

Provisioning mappings cover **Kali / Debian / Ubuntu**, **Fedora**, **Arch**, and **macOS**
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

cron worker                 ok   internal worker pid=...

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
also starts or reuses the single portable background cron worker. Setup,
migration and startup seeding never install, enable, repair or remove OS
scheduler units. Defaults live only in `~/.pwn/cron/jobs.yml`; the worker
must be running for automatic execution (start it again after reboot with
`pwn setup --cron`). Manual commands remain available without a worker. Live Policy files (`policy.json`,
`policy_traj.jsonl`) are created on first agent turn when `ai.agent.policy`
is on.

Schema `v8` seeds the enabled `session_cleanup` hygiene job, daily at 03:45
in the scheduler's local timezone. First launch also seeds it through
`PWN::Cron.install_defaults`. The bundled `etc/default_cron/session_cleanup.rb`
is installed to `~/.pwn/cron/session_cleanup.rb`; managed copies refresh on
subsequent launches/migrations, while unmarked custom helpers are preserved.
An existing job named `session_cleanup` keeps its ID, schedule, enabled state,
payload. Legacy native scheduler files are left untouched for an explicit
operator-approved removal; they are never refreshed or re-enabled by setup.
New jobs defer cleanup until their first scheduled time, rather than deleting
during initial catch-up.

Fresh installs now seed only this job, with `SessionCleanup.coordinate`: shared
evidence-first maintenance, memory consolidation, then separate learning,
mistakes and policy retention phases. Existing split maintenance schedules are
preserved until explicitly consolidated after a safe matched-code deployment.
Curriculum schedules require explicit creation; startup and repeat migrations
never recreate deleted curriculum jobs. See [Cron](Cron.md) for opt-in templates
and schedule-only deletion. Already-running old binaries must be upgraded before
their startup/config-refresh hooks can be relied on to honor the new defaults.

**Housekeeping never uses systemd or any other native scheduler.**
`session_cleanup`, `learning_consolidate_nightly`, and `pwn_stores_lean_nightly`
run only through PWN's built-in cron worker or manual commands. Native job
installers explicitly skip them with `housekeeping_internal_only`; this also
covers renamed payloads that invoke `SessionCleanup` or `session_cleanup.rb`.
Generic scheduler APIs remain available for unrelated custom jobs. Native
worker launchers mark their execution context and exclude housekeeping;
legacy PWN systemd cgroups are also excluded. An inherited terminal
`INVOCATION_ID` alone is not a scheduler context.

Existing installations require an explicit operator decision before stopping
legacy services or processes. Inventory `pwn-cron-*.timer` and `.service`, map
job IDs to `jobs.yml`, preserve custom schedules, then (only with approval)
disable and stop the housekeeping timers/services and the legacy shared
worker service, archive their unit files/drop-ins, remove those exact files,
and run the user manager's daemon-reload. Do not remove unrelated custom job
units or change lingering globally. Coordinate old clients before deploying
the new code, retain `jobs.yml` unchanged, then start/reuse one internal
worker and verify its PID and guarded tick. Do not run cleanup to validate
this transition or re-enable legacy housekeeping units.

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
Version 7 backs up unreferenced unsummarized sessions before a guarded `Sessions.delete`
call that bypasses the ordinary age pin. `/sessions list` shows only valid
LLM-summary-title or valid dependency-backed sessions, excluding sessions with
attributed dependency errors. Active leases protect bytes even when a session
is hidden. Explicit resume and `Sessions.list(include_hidden: true)` still reach
hidden records. `dependencies` lists files **referencing this session**, not
files it depends on. Per-session `dependency_errors` contains only safely
attributed errors; `unresolved_dependency_stores` reports global uncertainty.
The index's `errors` remains the unattributed store list: it blocks apply and is
reported as `unresolved_store_remediation`, never copied onto every session.
Parsed rows are validated independently so an invalid shared row does not
invalidate unrelated good records.
The shared index follows defined structural fields, not ID-looking text.
Dependency-backed sessions remain visible and resumable, not archived away.
Vault/config/credential payloads and historical backups are not scanned.
Current writers hold per-session lifetime leases; legacy installed writers
without that protocol cause conservative ownership uncertainty. Inspect without deleting:
`ruby ~/.pwn/cron/session_cleanup.rb --dry-run`.

`--apply` backs up eligible transcript/metadata bytes under
`~/.pwn/session_cleanup_archive/<run>/` (directories 0700, files 0600), outside
`/sessions list`. Atomic, fsynced backups are SHA-256 verified before deletion;
file identities/hashes, title classification, reference stores and process state
are rechecked under per-ID/transcript locks. `ledger.json` records exact IDs,
hashes, skips and completed deletions; dry-run JSON contains metadata only and
creates no archive. Backups are for recovery, not an automatic reference
resolver: referenced placeholders remain in the active list until a separately
verified archive-aware lookup policy exists. Invalid learning evidence rows with
one proven session owner can be removed with their inactive session under the
Learning writer lock. The entire original shared store is backed up; only the
invalid row is removed, keeping unrelated rows byte-for-byte. Prepared/committed
`dependency_removals` ledger entries record hashes, row locators and backup paths.
Approval and locked rechecks bind both transcript and dependency fingerprints.
Valid references still protect a session; conflicting valid/invalid references,
multiple owners, and attributed stores without a cooperating permanent writer
lock report `unresolved_dependency_remediation` and remain physically untouched.
Memory, its archive, and Mistakes now use permanent reentrant store transactions
covering complete read-modify-write operations, including Learning consolidation
and noise purging. Single-owner invalid map entries can be removed under those
locks with whole-store backups and prepared/committed ledgers; unrelated map
entries retain their values (JSON formatting may change). Stale expiry snapshots
cannot remove refreshed memory. Corrupt Mistakes input raises rather than
falling back to an empty map. Other stores (including disputed learning, findings,
policy trajectories and event logs) remain unresolved when no safe targeted writer
protocol exists. Deploy all cooperating writers before enabling remediation; old
installed writers do not honor the new locks. No shared store is wiped. The process
checks and advisory locks do not claim a transactional guarantee against
arbitrary non-cooperating external writers.

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

Routine maintenance supports multiple simultaneously running upgraded clients;
there is no blanket shutdown requirement. Evidence migration takes exclusive
nonblocking leases per source transcript through index publication, skips active
sources (`evidence_migration.deferred_active_sessions`), and revisits them on a
later run after their writers finish. Unrelated eligible sessions can still be
removed. A busy Learning writer returns
`evidence_migration.deferred: learning_writer_active` with `apply_blocked: true`
rather than waiting or interrupting the writer; retry on a later cron tick or
manual invocation. The permanent maintenance lock admits one applying owner;
a second receives `Session maintenance already running` immediately. Title
workers and durable job dependencies retain their existing protections.
This is routine maintenance, not the explicitly offline layout migration.

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

The `upgrade_pwn.sh` → `build_gem.sh` validation gate still runs through
`rvmsudo` on multi-user RVM installations. Its merged stdout/stderr is streamed
and retained in the invoking user's `~/.pwn/logs/build-gate.log` (mode 0600,
last 1 MiB, replaced on the next gate). The path is printed before execution
and on failure; installation does not continue after a failed gate. `rake spec`
also prints each failure immediately and reports the RSpec child's exit status
or signal, so a later terminated example cannot hide earlier failure details.
A signal report is diagnostic evidence, not a claim about who sent the signal.

The legacy `./install.sh` / `packer/provisioners/pwn.sh` bash paths still
work, but they now simply delegate to `pwn setup` - the `case $os` package
lists have been consolidated into `PWN::Setup::NATIVE_GEMS` / `::TOOLCHAIN`.

---

## Docker / Packer / Vagrant / CI

`pwn setup` is the single provisioning entry point for every image builder:

Start from an image with a supported Ruby, RubyGems, compiler and required
native gem headers already installed. A bare `kalilinux/kali-rolling` image does
not establish those prerequisites. Review the repository Dockerfile/provisioners,
pin the base and gem version for reproducible deployments, then explicitly run
`gem install --verbose pwn` and the chosen `pwn setup --profile` command.
Image build success is not live provider/radio/browser acceptance.

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
(one per `PWN::` module, plus `references/` when the source has CWE/NIST/URLs) are
copied to `~/.pwn/skills/pwn/` and **are** overwritten on
`pwn setup --migrate` / first launch so they stay in sync with `lib/pwn`.
`bundle exec rake` does not rewrite `etc/default_skills/pwn`. `rake module_skills`
is the explicit regenerate. A spec or rake run that writes the checkout
leaves a local `SKILL.md` edit, and the next `upgrade_pwn.sh` merge aborts.
The upgrade saves modified generated module `SKILL.md` files in a named Git
stash before merging; it does not automatically reapply those stale files.
Skills marked `preserve: true` and unrelated edits are left alone.

For a clone already blocked before it can obtain this fix, no reclone is needed:

```bash
cd /opt/pwn
git stash push -m 'pwn: preserve legacy generated skills before upgrade' -- etc/default_skills/pwn
./upgrade_pwn.sh
```

The stash preserves the prior skill edits for review with `git stash list` and
`git stash show -p`. Do not blindly pop it after upgrading: that restores stale
generated files and can recreate the conflict. The one-time command saves all
edits under that skill subtree, including any hand-edited skills; recover those
selectively after reviewing them. Other local changes are not stashed.

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
pwn[CURRENT_VERSION]:003 >>> PWN::Plugins.constants.count   # => 107
pwn[CURRENT_VERSION]:004 >>> PWN::SAST.constants.count      # => 48
pwn[CURRENT_VERSION]:005 >>> pwn-ai                         # launches agent TUI
```

**Next:** [Configuration](Configuration.md) · [General Usage](General-PWN-Usage.md) · [Persistence](Persistence.md)

[← Home](Home.md)
