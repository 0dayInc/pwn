# Agent Tool Registry

`PWN::AI::Agent::Registry` (`lib/pwn/ai/agent/registry.rb`) collects every
LLM-callable function into named **toolsets**. A persona is granted a subset of
toolsets; the JSON-Schema for each tool is what the model actually sees.

![Tool registry](diagrams/agent-tool-registry.svg)

## Toolsets to tools  (16 toolsets · 150 tools)

| Toolset | Tools | Backed by |
|---|---|---|
| `http` | `http_proxy_start` · `http_proxy_stop` · `http_proxy_entries` · `http_proxy_rules` · `http_replay` | `PWN::Plugins::MitmProxy`: native HTTP HAR capture/replay; opaque CONNECT tunnels |
| `terminal` | `shell` · `job_run` · `job_status` · `job_tail` · `job_result` · `job_kill` | Foreground host commands plus `PWN::Plugins::Jobs` durable supervisors |
| `pwn` | `pwn_eval` · `sbom_scan` · `r2_functions` · `r2_disasm` · `gdb_run_to_crash` · `nmap_scan` · `nuclei_scan` · `browser_goto` · `loot_query` | `TOPLEVEL_BINDING.eval` in the live REPL process, after `ToolGuard`; SBOM engines via `PWN::Plugins::SBOM` store CVE leads as recon observations, not findings; r2pipe JSON via `PWN::Plugins::Radare2`; gdb MI3 crash reports via `PWN::Plugins::GDBMI`; nmap XML ingest/diff via `PWN::Plugins::NmapIt`, which skips a known port unless `refresh: true`; nuclei/httpx JSONL via `PWN::Plugins::Nuclei` writes a recon observation (a template match is not a finding) and accepts a `Recon.handoff` record; TransparentBrowser navigation captures screenshot/DOM/HAR via `browser_goto`; engagement loot via `PWN::Plugins::Vault` |
| `mcp` | `mcp` | `PWN::AI::MCP` session broker → any `PWN::AI::MCP::*` stdio client |
| `memory` | `memory_remember` · `memory_recall` · `memory_forget` · `memory_clear` · **`memory_lean`** | `PWN::Memory` → `~/.pwn/memory.json` |
| `skills` | `skills_consolidate` · **`skills_recall`** · `skill_list` · `skill_view` · `skill_create` · `skill_add_reference` · `skill_delete` · `skill_migrate_legacy` | `~/.pwn/skills/<name>/SKILL.md` (**[agentskills.io](https://agentskills.io) spec**; legacy flat `*.md` auto-migrated) |
| `sessions` | **`session_recall`** · `sessions_list` · `sessions_view` · `sessions_current` · `sessions_delete` · `sessions_stats` · **`sessions_lean`** · `artifact_read` · `artifact_grep` · `artifacts_list` · `artifacts_get` · `artifact_put` · `artifact_get` | `PWN::Sessions` → `~/.pwn/sessions/`; `PWN::Plugins::ArtifactRegistry` → `~/.pwn/artifacts/` |
| `learning` | `learning_note_outcome` · `learning_reflect` · `learning_distill_skill` · `learning_stats` · `learning_outcomes` · `learning_consolidate` · `learning_reset` · `learning_auto_introspect_toggle` · **`learning_gc_stores`** · **`learning_purge_noise`** · **`mistakes_list`** · **`mistakes_record`** · **`mistakes_resolve`** · **`mistakes_reset`** · **`mistakes_lean`** · **`reward_judge`** · **`reward_prm`** · **`reward_sentinel`** · **`reward_preferences`** · **`reward_export_dpo`** · **`reward_warm_sentinel`** · **`reward_scrub_preferences`** · **`reward_preference_balance`** · **`curriculum_practice`** · **`curriculum_train`** · **`curriculum_hindsight`** · **`curriculum_offline_judge`** · **`curriculum_preference_balance`** | `PWN::AI::Agent::Learning` + `Mistakes` + `Reward` + `Curriculum` → `~/.pwn/learning.jsonl` + `~/.pwn/mistakes.json` + `~/.pwn/preferences.jsonl` + `~/.pwn/curriculum/` + `~/.pwn/finetune/` |
| `reward` | **`reward_generator_mix`** | `PWN::AI::Agent::Reward.generator_mix` → online preference source-mix controller (`preferences.jsonl`) |
| `curriculum` | **`curriculum_practice_kpi`** | `PWN::AI::Agent::Curriculum.practice_kpi` → `~/.pwn/curriculum_kpi.jsonl` |
| `metrics` | `metrics_summary` · `metrics_reset` | `PWN::AI::Agent::Metrics` → `~/.pwn/metrics.json`. ESR is `verified_exploit_tools / vulnerable_tools`. ASR is `successful_attacks / total_attack_attempts`. |
| `policy` | **`policy_stats`** · **`policy_evaluate`** · **`policy_recommend`** | `PWN::AI::Agent::Policy` → `~/.pwn/policy.json` + `~/.pwn/policy_traj.jsonl` |
| `extrospection` | `extro_snapshot` · `extro_drift` · `extro_observe` · `extro_observations` · `extro_intel` · **`extro_watch`** · **`extro_verify`** · **`extro_rf_tune`** · **`extro_osint`** · **`extro_serial`** · **`extro_telecomm`** · **`extro_packet`** · **`extro_vision`** · **`extro_voice`** · `extro_correlate` · `extro_stats` · `extro_reset` · `extro_auto_toggle` | `PWN::AI::Agent::Extrospection` (+ Serial/Packet/OCR/Voice/BareSIP/TransparentBrowser/GQRX) → `~/.pwn/extrospection.json` |
| `cron` | `cron_list` · `cron_create` · `cron_run` · `cron_enable` · `cron_disable` · `cron_remove` | `PWN::Cron` → `~/.pwn/cron/jobs.yml` |
| `swarm` | `agent_list` · `agent_spawn` · `agent_ask` · `agent_debate` · `agent_broadcast` · `swarm_bus` · `swarm_list` · `agent_roster` | `PWN::AI::Agent::Swarm` → `~/.pwn/agents.yml` + `~/.pwn/swarm/` |
| `manifest` | `host_os_type` | YAML tool declarations in `lib/pwn/ai/tools/*.yaml` via `PWN::AI::Agent::Manifest` |

The `learning` toolset is deliberately large: **Mistakes** (negative feedback),
**Reward** (outcome and process judges, sentinel, preference ledger) and
**Curriculum** (self-play, hindsight relabel, optional LoRA gate) are facets of
the same self-improvement loop - see [Reinforcement Learning](Reinforcement-Learning.md).
The thin `reward` and `curriculum` toolsets expose controller and KPI surfaces
(`reward_generator_mix`, `curriculum_practice_kpi`) so personas can grant just
those without the full learning surface.
`shell` and `pwn_eval` share `PWN::AI::Agent::ToolGuard`
(`lib/pwn/ai/agent/tool_guard.rb`) before they run. The guard remaps common
wrong keys, rejects ellipsis placeholders, refuses bash-only syntax unless
`ai.agent.shell_bash` is true (default runner is `/bin/sh`).

The `policy` toolset is inspect-only. `policy_stats`, `policy_evaluate`, and
`policy_recommend` read the live Q / REINFORCE table. Reset is Ruby-only, so a
tool call cannot wipe the weights. `Registry.rank` may add a small Q-advantage
after a pair has been visited at least twice. Planning still owns the work.

**Store hygiene tools** (`memory_lean`, `sessions_lean`, `mistakes_lean`,
`learning_gc_stores`) trim ephemeral or oversized state without dropping
protected operator preferences, open mistakes, or gold outcomes.

## Dynamic tool-set slimming (`ai.agent.tool_router`)

The normal `Loop.run` path uses `core_only: true`. The central registry also
includes `mcp` when the original request names MCP, a discovered backend, or
one of its declared tools. Backend names and tool names come from
`PWN::AI::MCP.backends`, not a ComboNation-specific router. Thus `combo.nation`,
`combo_nation`, and `PWN::AI::MCP::ComboNation` expose the same broker, even in
core-only mode or with a zero top-K budget. Unrelated core-only prompts remain
unchanged, and explicit toolset exclusions and availability checks still apply.

The advertised MCP schema includes the local backend catalog. Use `list_tools`
for the selected backend's live argument schemas, then `call_tool` with a JSON
`arguments` object. Sessions persist across calls and menu IDs such as `5.10`
must stay strings. Catalog discovery reads local metadata only: it does not
launch a server or enable hardware. Hardware still requires explicit opt-in.

Shipping every schema on every turn overwhelms a small local model - the
choice space is huge and it mis-routes (for example, picks an RF tool for a git
question). When `ai.agent.tool_router: true` **and** `Loop.run` passes the
user request through as `relevance:`, `Registry.definitions` shrinks the
pool to:

```text
CORE_TOOLS / DEFAULT_PREFERENCE (same list):
memory_recall · session_recall · skills_recall · pwn_eval · shell
mistakes_record · mistakes_resolve · learning_note_outcome · memory_remember · skills_update
artifact_read · artifact_grep
job_run · job_status · job_tail · job_result · job_kill
            + top-K keyword-ranked matches for THIS request
              (ties break on Metrics per-engine success_rate, then
               ai.agent.tool_preference)
```

```ruby
PWN::AI::Agent::Registry.definitions(relevance: 'nmap sweep 10.0.0.0/8', top_k: 10)
PWN::AI::Agent::Registry.rank(query: 'run a shell command')   # inspect ranking
PWN::AI::Agent::Registry.preference_order                     # Env / DEFAULT_PREFERENCE
PWN::AI::Agent::Registry.toolsets                              # -> the 16 names above
PWN::AI::Agent::Registry.all.count                             # -> 146 (after discover)
```

Frontier engines leave `tool_router` off (unless you set it) and receive the
full set. Local engines (`ollama` / `openwebui`) default `tool_router` to on.

## Durable long-running jobs

Use `job_run(command:, max_runtime:, cwd:, env:, idempotency_key:)` for fuzzers,
full scans, and Ghidra headless analysis. It returns a job ID rather than holding
a tool call open. A separate Ruby supervisor owns the workload, persists status
and logs under `~/.pwn/jobs`, and remains alive when the launching agent exits.
`max_runtime: 21600` permits six hours; `0` means no runtime limit. The supervisor
enforces that deadline without requiring polls. This runtime does not enter
Dispatch's foreground timeout budget or its +180-second retry ladder.

Poll `job_status(id:)` for state and exit/signal. Read `job_tail(id:, offset: 0)`
and carry its `next_offset` into the next read; log pages are capped to the inline
budget. Log `eof` is only the current end of the log, not task completion.
Call `job_status` without an ID to rediscover recent jobs after changing sessions.
Use a stable `idempotency_key` for launch retries; do not rerun the command to poll
it. `job_kill` requests cancellation; confirm the terminal status afterward.
These job tools are in the default core set, subject to toolset exclusions.

`job_run(jobs: [...])` also runs its job graph inside a detached supervisor.
`shell(background: true, max_runtime: ...)` provides the same detached lifecycle;
the runtime predictor can route long shell work before Dispatch injects a timeout.
`fuzz_campaign(action: start, ...)` forwards runtime, working directory, environment,
session and idempotency settings to the same supervisor. No named-binary regex
is required for these routes. Host reboot/process-manager cgroup termination is
not session persistence: workloads are not automatically restarted after those
events, and lost supervision must not be reported as successful completion.

## Lossless tool-result paging

Oversized handler results are saved before redaction/quarantine to
`~/.pwn/artifacts/<session>/<sha8>.bin`. The inline summary carries the handle,
full SHA-256, byte count, serialization type, bounded preview, and execution
status (including nonzero exits/timeouts). Raw string results retain every byte;
structured results use JSON, with base64 wrappers for non-UTF-8 strings.
Files are private (0600, directories 0700). A short-hash collision fails rather
than overwriting different bytes. Spill errors are explicit tool failures.

`PWN::Env[:ai][:agent][:artifact_max_tokens]` optionally sets N. Without a
provider tokenizer, a byte is treated as a conservative token upper bound:
spill may happen early, never on the assumption that arbitrary dumps average
four bytes per token. The default is 6000 (local engines: 1024), with a minimum
of 1024 to leave room for the handle/metadata. Existing `result_max` and per-tool
caps can lower the default. This is a runtime fallback; existing config files
are not rewritten.

`artifact_read(handle, offset, length)` uses byte offsets, clamps page length
to the inline budget, and returns `next_offset`/`eof`. Handle pages default to
base64 for exact reconstruction; request `mode: text` for inspection. Legacy
path/ref readers remain available. `artifact_grep(handle, regex, offset)` returns
bounded per-line search results with byte offsets and a continuation cursor.
Regexes match whole binary lines (first match per line), not page fragments;
lines over 64 MiB raise an explicit error directing the model to `artifact_read`.
Regex execution is time-limited. Both readers
are core tools (subject to explicit toolset exclusions). Follow cursors rather
than assuming the requested length was returned. The loop keeps only its bounded
recent tool history; paging does not accumulate the full dump in context.
Credential redaction still applies to inline views; the saved bytes are unchanged.

## Payload validation diagnostics

`invalid_payload` responses include `rule_id`, `match`, `offset`, and `remedy`.
For rejected shell placeholders and syntax, `match` is the actual rejected
substring and `offset` is its zero-based byte position in the original decoded
command, including UTF-8 and base64 input. The legacy `offending_token`,
`byte_range` (exclusive end), `hint`, and `suggestion` fields remain available.
Missing fields and schema constraints have no command-text offset (`null`);
schema denials also identify the argument using `data_pointer`.

Ellipses in literal data pass without an escape hatch: Ruby is tokenized with
Ripper, and shell words are scanned with quote/escape state and queued heredoc
delimiters (including `<<-` tab stripping). Ruby strings, percent literals and
heredocs are data; parsed ranges and argument forwarding are valid code.
Bare elided commands and incomplete Ruby stubs such as `def foo(<3dots>)` are
denied with the same diagnostics. Explicit `placeholder_ok: true` still skips
the placeholder check, but never bypasses Ruby parsing or shell execution.
For quoting/transport, use `encoding: "base64"` and the encoded command in `data`.
Base64 is decoded before validation and is not a bypass: preserve the explicit
placeholder opt-in when needed. Neither option overrides shell syntax, size,
or policy restrictions. Each denial's `remedy` names the applicable correction.

## Required artifact contract

At intent classification, `Loop.run` precommits explicit output destinations as
an immutable `required_artifacts` list. Relative paths resolve against the
initial working directory; input/read paths are not output obligations. The
same list drives the prompt checklist, dispatch snapshots and final-answer gate.
Artifact-bearing requests cannot take greeting/how-to/recall text-only shortcuts.

A successful write-effect call must change the destination's host snapshot.
The host then records stat and SHA-256 readback in internal tool-message metadata,
bound to this turn's contract ID. Finalization rechecks the current file against
that evidence. Textual delivery claims, mere existence, old-turn observations,
and files changed after readback cannot satisfy the gate. A proven current-turn
write delta takes precedence over filesystem timestamp clock-tick lag.
Nested calls inherit the contract and restore it on return. Historical mistake
entries are not deleted by this enforcement.

## Retry checkpoints

The identical-payload checkpoint distinguishes retries from successful repeats.
A structured nonzero exit or timeout resets that payload's repeat count and
does not extinguish the payload through the repeated-failure guard. The command
can therefore be retried verbatim; timeout retries still use Dispatch's existing
deadline escalation and cumulative budget. Successful repeats retain the
checkpoint. Policy denials, exhausted budgets, checkpoint responses, and text
in stdout do not grant an execution-failure exemption. Actual command failures
remain recorded; the exemption does not erase historical mistake entries.

## Tool preference (`ai.agent.tool_preference`)

When keyword fit and other rank scores tie, the registry prefers this
default order:

```text
memory_recall · session_recall · skills_recall · pwn_eval · shell
mistakes_record · mistakes_resolve · learning_note_outcome · memory_remember · skills_update
artifact_read · artifact_grep
job_run · job_status · job_tail · job_result · job_kill
```

Set `ai.agent.tool_preference` in `~/.pwn/pwn.yaml`, or pass `order:` /
`preference:` into `Registry.definitions`, `.rank`, or `.apply_preference`.
An explicit empty list turns preference off (no Env / default fallback).

Learned facts and this session are injected (MEMORY / RECENT TURNS), not
first tools. Preference then lists `pwn_eval` before `shell`. `sessions_view`
is not a CORE tool. There is no separate ACT_PREFERENCE.

Keyword fit stays the primary signal. Preference is a smaller bonus plus a
stable sort after the router slims the pool.

`Policy` uses the same list when it suggests a next action in the prompt.

## Finding evidence and reproducible reports

`finding_record` requires a command/code `poc`, ordered `reproduction_steps`
(setup, commands, expected observations), and an evidence-based
`severity_justification`, alongside its CVSS/CWE/asset/remediation fields.
Provide `evidence_paths` or `artifact_handles` (or both). Each handle is either
a string or an object containing `handle`, optional `kind` (`pcap`, `screenshot`,
`crash`, `poc`, `evidence`), optional display `label`, and optional expected
full `sha256`. Use artifact middleware handles such as `session/sha8.bin`,
`sha256:<64 lowercase hex digits>`, or the legacy bare full SHA-256 returned
by `ArtifactRegistry.put`. Handles are validated, not treated as file paths.

The host resolves each handle, computes the full SHA-256 and byte count, checks
any supplied digest, and preserves an engagement-owned copy. The persisted
finding includes `evidence_artifacts` with handle, kind, label, source `path`,
durable `stored` path, hash, and size. Malformed, missing, symlinked or tampered
handles fail recording. Verification/retest and combined-impact evidence are
also attached to the finding; previous evidence snapshots remain linked.

Export with `finding_record(op: 'export', engagement_id: 'fixture',
dir_path: '/tmp/findings-report', report_name: 'findings')`. Generated reports
include the supplied PoC instructions and justification with evidence hashes
per finding. HTML/Markdown include portable links, raster screenshots, and
escaped PoC previews; JSON/SARIF retain structured linkage. Distribute the
adjacent `attachments/` directory with the reports. Every attachment is checked
against its recorded digest and size; missing or changed durable copies and
tampered export targets fail explicitly. Active SVG/HTML is never embedded as
a screenshot. Full PoC text is downloadable even when its preview is bounded.
Evidence packaging currently reads one full attachment into memory at a time.
Hashes establish byte identity, not successful exploitation;
new records remain `not_executed` until explicitly verified. Direct legacy
`Findings.record_structured` callers may omit the new narrative fields (the
existing PoC becomes their reproduction step), but the agent tool requires
them. Original-source removal/tampering remains detectable by
`Findings.evidence_verify`; durable copies are checked too.

Findings can declare outgoing `enables: [finding_id]` links. Use
`finding_record(op: 'link', id: source_id, enables: [target_id])` to link
already recorded findings. `chain_impact` takes ordered source-to-impact
`ids`, combined-impact evidence, a severity justification, and reproduction
steps. Reports rank the resulting paths by their scoped combined-impact
assessment; linked constituents remain in technical details rather than
appearing as separate summary priorities. See
[Recon / Findings API](Recon-Findings-API.md#directed-attack-paths-and-combined-impact).

## Adding a tool

```ruby
# lib/pwn/ai/agent/tools/my_thing.rb
PWN::AI::Agent::Registry.register(
  name: 'my_thing_do',
  toolset: 'my_thing',
  description: 'One-line summary the LLM will read.',
  parameters: {
    type: 'object',
    properties: { target: { type: 'string' } },
    required: ['target']
  }
) do |args|
  PWN::Plugins::MyThing.do(target: args['target'])
end
```

Drop the file in `lib/pwn/ai/agent/tools/`. It is auto-loaded on next launch.

## Restricting a persona

```yaml
# ~/.pwn/agents.yml
recon:
  role: "Passive OSINT only. Never touch the target directly."
  toolsets: [terminal, pwn, memory, extrospection]   # no swarm, no cron
  engine: ollama
```

**See also:** [pwn-ai Agent](pwn-ai-Agent.md) · [Mistakes](Mistakes.md) ·
[Reinforcement Learning](Reinforcement-Learning.md) · [Swarm](Swarm.md)

[← Home](Home.md)
