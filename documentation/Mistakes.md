# Mistakes — The Negative-Feedback Loop

`PWN::AI::Agent::Mistakes` is the **negative** half of the pwn-ai learning
loop. Where [Learning](Skills-Memory-Learning.md) records *what worked* and
[Metrics](Skills-Memory-Learning.md) records *how often* a tool worked,
Mistakes records **specific failure patterns** with a stable fingerprint so
the agent can (a) recognise it is repeating itself, (b) be told exactly what
**not** to do again in every future system prompt, and (c) capture the **fix**
once one is found so the avoidance lesson becomes an actionable correction.

![Mistakes negative-feedback loop](diagrams/mistakes-negative-feedback.svg)

## The failure fingerprint

A "mistake" is keyed by `sha12(tool + normalised_error)`. Normalisation strips
volatile bits — paths, hex addresses, `:LINE`, `port N`, timestamps, UUIDs,
PIDs — so `NoMethodError … at foo.rb:42` and `… at foo.rb:99` collapse to
**one** signature and its `:count` climbs. **That count *is* the repeat
detector**, and it survives across sessions.

| Field | Meaning |
|---|---|
| `signature` | 12-hex-char sha of `(tool, normalised_error)` — stable across runs |
| `tool` | component the failure was in (`shell`, `pwn_eval`, `assumption`, `assistant_answer`, a module name…) |
| `error` | normalised error text (paths/lines/addrs/ts stripped) |
| `count` | **cross-session** recurrence count — drives `[REPEATING]` at ≥ 3 |
| `resolved` / `fix` | set by `mistakes_resolve` — promoted to a `PWN::Memory` `:lesson` |
| `regressed` | auto-set when a *resolved* signature recurs — reopened as `[REGRESSED]` |
| `sessions` | last 10 session_ids that hit it |

## How the loop closes (why it does **not** repeat mistakes)

```text
Loop.run --(tool failure)---------> Mistakes.record         (persist + count++)
Loop.run --(same sig, count≥3)----> guard_repeated_failure  (uses PERSISTENT count →
                                                             fires on the 1st recurrence
                                                             in a NEW session, not the 3rd)
Loop.run --(failure w/ known fix)-> inline correction_hint  ("seen 5×, sig=…, KNOWN FIX: …"
                                                             → self-corrects NEXT iteration)
Loop.run --(user says "wrong")----> check_user_correction   (flip last outcome + record)
PromptBuilder <-------------------- Mistakes.to_context     (KNOWN MISTAKES + KNOWN FIXES)
model --(tool call)---------------> mistakes_record / mistakes_resolve
```

## Four ingest paths — nothing slips through

| Source | Trigger | What is recorded |
|---|---|---|
| `:tool` | any tool dispatch returns `success:false` / raises | *automatic* — `Loop.record_metrics` |
| `:loop` | iteration budget exhausted with no final answer | *automatic* — `Loop.run` epilogue |
| `:user_correction` | next user message matches `CORRECTION_RX` (*"no that's wrong"*, *"still broken"*, *"try again"*, …) | `check_user_correction` — also flips the previous `Learning` outcome to `success:false` |
| `:model` | the model itself calls `mistakes_record` | wrong assumption, wrong file, hallucinated API — failures that are **not** dispatch errors |

## Tools

| Tool | Does |
|---|---|
| `mistakes_list` | count-sorted fingerprints (signature · tool · error · count · resolved · fix) |
| `mistakes_record` | proactively fingerprint a semantic mistake YOU just made |
| `mistakes_resolve` | attach the **fix** → promoted to `PWN::Memory` `:lesson` **and** handed straight back inline via `correction_hint` on the next recurrence. If the same sig recurs it auto-reopens as `[REGRESSED]`. |
| `mistakes_reset` | wipe `~/.pwn/mistakes.json` (new engagement) |

## What the model sees every turn

`PromptBuilder` injects `Mistakes.to_context` between the `LEARNING` and
`TOOL EFFECTIVENESS` blocks:

```text
KNOWN MISTAKES (do NOT repeat — call mistakes_resolve once fixed)
  ✗ [a1b2c3d4e5f6] shell ×4 [REPEATING]: nmpa: command not found
  ✗ [7f8e9d0c1b2a] pwn_eval ×2 [REGRESSED]: nomethoderror: undefined method `scan_range' — last fix (insufficient): use fast_scan_range
KNOWN FIXES (apply these instead of repeating the mistake)
  ✓ [c0ffee123456] shell: connection refused port N — FIX: start ZAP first via PWN::Plugins::Zaproxy.start
```

…and every failed dispatch gets an **inline** postscript:

```text
[pwn-ai/mistakes] seen 4× across 3 session(s), sig=a1b2c3d4e5f6 | KNOWN FIX: binary is spelled `nmap`
```

so the very next iteration self-corrects without re-discovering the fix.

## Regression detection

Resolving a mistake does **not** delete it. If the same signature fires again
after `mistakes_resolve`, `record()` clears `:resolved`, sets `:regressed`,
and the entry re-enters the `KNOWN MISTAKES` block tagged `[REGRESSED]` with
its (now-insufficient) previous fix shown inline — the strongest possible
"your last fix didn't hold" signal.

**See also:** [Skills, Memory & Learning](Skills-Memory-Learning.md) ·
[Extrospection](Extrospection.md) · [Persistence](Persistence.md) ·
[pwn-ai Agent](pwn-ai-Agent.md)

[← Home](Home.md)
