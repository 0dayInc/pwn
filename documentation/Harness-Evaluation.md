# Deployment fingerprints and fair harness evaluation

## Evidence-backed improvement lifecycle

This extends the existing `Verification` → `Reward` → `Learning` ledger and
`PolicyEvaluation`/RSpec harness; there is no second evaluator or automatic
self-promotion loop.

### Completion accounting

`Reward.resolve_outcome` exposes `verified_completion` independently of the
legacy judge-quality `success` field. It is true only for complete host check
coverage, false for a verifier failure, and null when evidence is unavailable.
`Reward.judge` preserves the evaluator's pre-verification `solved` verdict in
`claimed_completion`. `false_completion` is true when that claim is independently
refuted, null when a claim has not been checked, and false for a checked pass or
an explicit nonclaim. These are **judge claims**, not a semantic classifier of
arbitrary assistant prose. Trusted host callers may explicitly supply the claim
to `resolve_outcome`; model-facing tools cannot create trusted checks.

`Learning.note_outcome` persists these fields without reinterpreting them.
`Learning.stats` reports completion claims, checked claims, verified completions,
false completions, and a false-completion rate whose denominator is **checked
claims**, not all attempts. The rate is null without checked claims. Old ledger
rows remain unknown for these new metrics; no migration fabricates labels.
Existing quality scores and training eligibility retain their previous semantics;
use verified completion, not legacy success rate, as acceptance evidence.

The executable harness independently counts a released success marker as false
success whenever the whole run is not PASS. Empty checks, failed processes and
resource-capped runs cannot hide behind correct bytes or vacuous `all?` checks.
The locked `completion_regressions.json` corpus records those source-reproduced
accounting defects; RSpec executes it alongside the existing CLI fault lanes.

### Turn observed failures into reviewable regressions

Use the exact persisted outcome ID, original request, and independently authored
expected bytes (never derive gold from the failed answer):

```ruby
recipe = PWN::AI::Agent::Learning.regression_task(
  outcome_id: failure_id,
  request: original_request,
  checks: [{ requirement: original_request, kind: :file,
             path: 'result.txt', expected: "correct\n" }]
)
# Within an RSpec example, using a fresh disposable fixture directory:
report = PWN::AI::Agent::Verification.run(recipe[:contract].merge(root: fixture_root))
expect(report[:status]).to eq(:pass)
```

Export is read-only and only accepts a persisted verifier failure among the most
recent 10,000 outcomes. The request digest and original requirement coverage must
match. Recipes contain source outcome identity, verification/contract SHA-256,
and a fixed `regression` split. Only relative file/JSON checks are supported;
commands, HTTP checks and raw tool traces are not mined or executed. Expected
content remains an operator-reviewed input, not independently attested history.
Review/redact the request and gold before saving a recipe in `spec/fixtures/harness`
and add its reproduction/setup under RSpec. Do not put an inspected regression in
the held-out split. The recipe itself verifies outputs; it does not autonomously
replay potentially destructive historical actions.

### Frozen acceptance and versioned local promotion

Reuse the existing policy CLI (`pwn-ai --policy evaluate`, `promote`, `rollback`)
and frozen snapshots, rather than updating live stores during evaluation.
`PolicyEvaluation.evaluate` runs the existing standalone worker with a cleared
environment and disposable HOME; off/baseline/candidate use frozen policy bytes
and independently checked tasks. The split-corpus executable experiments clone
frozen training HOMEs per trial, check input/snapshot hashes and reject duplicate
cross-split prompts or inputs. The held-out set is public and fixed: it tests
infrastructure and this local controller, not general live model intelligence.

Promotion still re-executes each submitted acceptance report, checks provenance,
requires both filesystem environments, rejects aggregate **and per-task**
regressions, and requires an independent held-out gain. Successful receipts now
include `receipt_version: 1`, `change_kind: routing_policy`, and
`acceptance_sha256` over deterministic fresh reports in addition to exact baseline
and candidate digests. Preserve the returned JSON in a distinct receipt file.
Rollback requires that successful versioned receipt and refuses intervening live
updates or changed backups. Old unversioned receipts are deliberately rejected;
retain their backups for explicit operator recovery rather than guessing a version.
These receipts are local audit records, not cryptographic attestations against a
hostile local writer. Both writes still require explicit approval, an explicit
live path and operator-attested stopped policy writers. This does not promote
arbitrary skills, model weights or external service changes.

## Deployment diagnosis

`PWN::RuntimeFingerprint.report(expected_root: '/intended/gem/lib')` is read-only.
The existing pwn-ai `/status` prints the report. The observer starts from `pwn.rb`,
before version/config loading. It reports PID, Linux boot ID/process start ticks
(or unavailable), observer timestamp, loaded version, activated gem root, actual
loaded Ruby source paths, SHA-256 observed on disk at compilation, and current
on-disk SHA-256. Changed or missing observed source and expected-root mismatches
require restart. Unknown pre-observer bytes are **not** reported as a match.

These are disk observations at compilation, **not VM bytecode attestation**.
Concurrent replacement during compilation, native extensions, evaluated strings,
and later monkey patches cannot be attested. `restart_required: false` means no
known mismatch, not proof every component is current. `pwn.rb` and the observer
itself were compiled before observation and intentionally remain unknown.

Preserve the original request, session ID, request checkpoint and evidence first.
Rebuild/install the intended tree, restart the process, and recheck the report.
Do not hot-reload an active request or equate restoring a checkpoint with safely
replaying a side effect. No automatic deployment or recovery mutation occurs.

## Offline acceptance (no credentials or provider calls)

```sh
HOME=$(mktemp -d /tmp/pwn-rspec-home.XXXXXX) bundle exec rspec \
  spec/integration/harness_evaluation_spec.rb \
  spec/integration/harness_package_spec.rb \
  spec/integration/harness_layout_spec.rb
```

RSpec owns acceptance and is included in the default offline `bundle exec rake`
gate. Callable execution/grading helpers and subprocess-only preloads live in
`spec/support/harness`; locked JSON manifests, independent gold and SHA-256 files
live in `spec/fixtures/harness`. Helpers are explicitly required, not recursively
loaded into the test process: the provider preloads must only run in isolated
children. There is no separate script-suite CLI. The package example builds and
executes the installed gem, not a mocked packaging check.

The package lane copies current tracked and nonignored untracked working files
into a temporary checkout, records every copied SHA-256, builds the actual gem,
installs it using `--local --ignore-dependencies` into a temporary GEM_HOME, and
runs that installation's **actual pwn-ai executable → CLI → Loop → provider →
Dispatch → shell**. It never stages the source checkout or modifies its installed
gem. Dependencies are read from existing gem paths; this is **not** proof of a
clean dependency installation. Source edits concurrent with snapshot creation
are represented by the copied-byte ledger, not an atomic Git revision claim.

Each subprocess gets an isolated temporary HOME and cleared environment. The
configuration loader and provider methods are replaced in a test-only preload;
transparent observers forward to real Dispatch, Learning and Swarm methods.
Fault stimuli supply public Loop runtime/steering options without replacing its
implementation. Loop, Dispatch, the verifier and tools remain real. The commands are local
file operations. HTTP/TCP provider access is rejected, and no credentials are
passed. This is not a general OS-level sandbox for arbitrary untrusted fixtures.
The preload is never selected by production configuration.

The fixed public tasks cover exact-file output, structured extraction, safe Ruby
coding and a nonexecuted parameterized-SQL toy classification. Grading reads
actual artifact bytes against authored literal expectations, separately from
provider text. An intentionally wrong artifact with a success claim must remain
FAIL with CLI exit 1 and `false_success: false`. The arbiter checks the explicit
`containing exactly ... followed by newline` literal against the observed digest;
this deliberately narrow grammar is not a general natural-language content judge.
The CLI now derives its exit code from the persisted outcome, not answer prose.
A detected false success is a defect and fails the evaluator itself. Fixture
outcomes are not evidence of live model competence.

`runtime_faults.rb` retains the older, explicitly labeled component fixtures.
`cli_faults.rb` adds actual executable → Loop → runtime → real shell fault lanes:

- **Compaction plus additive steering:** real writes/reads generate long context,
  a small runtime window forces EngagementMemory, a public Steering submission
  adds a second deliverable, and independent checks require both actual files.
- **Provider retry after a successful effect:** the fake provider raises EOFError,
  the real retry path recovers, and the effect log must still contain one write.
- **Cancel during a blocked provider:** after one real write, Steering cancels
  the sleeping provider; the runtime must be cancelled, no final claim released,
  and the CLI nonzero. This is not a native-terminal Ctrl+C test.
- **Checkpoint restart:** one real mutation times out, the process exits abruptly,
  then a new CLI process restores the same request and refuses duplicate replay.
- **Hard resource cap and restart:** after at most 35 seconds of bounded executable
  startup, an observed provider-fault readiness marker arms a four-second hard
  process-group cap. The supervisor records INCOMPLETE, restores the real checkpoint
  and proves that the uncertain mutation is not repeated. Missing readiness cannot
  pass this lane. This separates cold gem activation from the injected blocked
  provider: killing a still-booting executable proves neither effect nor recovery.

The fault preload supplies public request/session/runtime/steering objects.
These are real CLI integration tests with injected controls; the separate
`session_acceptance.rb` exercises public session selection and replacement approval
without injected runtime objects. They cover finite stimuli, not every provider HTTP
retry implementation. Package acceptance runs these same lanes against installed
gem code and checks deployment fingerprints. No live provider is contacted.

The additional baseline `timeout-replay` task executes one append before timeout,
refuses the second mutation, and must exit nonzero. The evaluator now reports
INCOMPLETE when a real observed Dispatch timeout prevents success; it does not
mistake an incomplete task for model-quality failure or hide it from results.

## Request-lifetime integration boundary

RequestRuntime persists tool start/end events and uncertain mutation fingerprints
before releasing results. An interrupted write is not automatically replayed,
including after checkpoint restore. Changing the action ID or timeout does not
change that fingerprint. This is conservative uncertainty handling, not proof of
remote exactly-once execution; spelling changes can still change the fingerprint.
Explicit caller timeouts are not increased by Dispatch on runtime-owned requests.
Legacy standalone Dispatch budgeting remains separate. Runtime-owned inference
has one total provider/profile attempt allowance; all six provider adapters use
private configuration snapshots and one transport attempt under that owner.

Runtime-bound OpenGoal files are session/request-keyed, private atomic JSON, with
a session pointer for bare `continue` in the same session. Legacy global records
are read only for their matching session. Checkpoint generations reject stale
writers. Loop also holds an exclusive per-session execution flock for the entire
request, acquired before runtime loading/checkpointing and released on return,
exception or process death. This is separate from Sessions' shared cleanup lease;
both apply to real CLI/TUI requests. Distinct sessions remain independent. The
session execution lock serializes OpenGoal pointer updates on production Loop
paths; individual atomic file writes are not a general multi-file transaction.
A new one-shot CLI session is not an automatic cross-session resume.

Explicit operator entry points:

```sh
pwn-ai --resume-session EXACT_SESSION_ID
pwn-ai --ai 'New objective' --verification-contract /path/to/authored.json
pwn-ai --replace-session EXACT_SESSION_ID --ai 'Replacement objective' \
  --verification-contract /path/to/replacement.json --approve-replacement
```

`--resume-session` rejects a replacement prompt/contract, selects the saved request
identity, and preserves its original objective, permissions and authored checks.
The existing TUI Sessions workspace and `/sessions resume ID` select exact stable
session IDs; a subsequent `continue` uses the same core restore path. A replacement
requires explicit approval, creates a **new** request identity and contract, and
retains the old checkpoint unchanged. It never edits the immutable original
objective or weakens an existing request's contract. `--resume RUN_ID` still means
TaskDAG resume and is not repurposed. Bare steering `replace:` remains an explicit
operator instruction; an existing authored contract is not replaced by steering.

Nested Loop turns now bind their own runtime artifact contract. Completed child
host receipts cross the enclosing Loop boundary only for a parent-required exact
path, matching child turn, current stat/readback/SHA-256 and a child started during
the parent request. Parent receipts retain child request/turn/action provenance.
The parent reruns its own literal/authored integration checks; child prose is never
proof. `swarm_acceptance.rb` executes agent_spawn → agent_ask → nested Loop and
real shell operations for correct, lying, preexisting/stale, missing and later
tampered artifacts. Negative task outcomes remain blocked/nonzero; PASS there
means the rejection invariant held, not that the requested work succeeded.

For nonreasoning OpenAI requests, explicit or configured temperature `0` is now
preserved in the actual serialized HTTP payload. The adapter regression intercepts
RestClient at the transport boundary rather than checking declared settings alone.
This is offline payload evidence, not a paired live reference-provider comparison.

Host-supplied verification contracts and tool permissions survive checkpoint
reload. Dispatch checks runtime permissions in addition to existing boundaries.
Additive steering verification binds the ordered original/amendment transcript,
not merely the last user line. Verifier events include original/effective request
and amendment digests, and report requirement character spans. An explicit
`answer` check compares actual final text and, when supplied, quoted/cited source
files through the bounded in-root verifier. No assistant PASS string is evidence.
These authored checks do not imply arbitrary research-answer semantic coverage.

These fixtures do not by themselves certify universal retry ownership, every
provider configuration, general semantic verification or scheduler correctness.
Those production requirements need their own acceptance evidence. An executable
arm which exposes a production defect remains FAIL and fails the aggregate
acceptance; actual correct artifact bytes do not override a nonzero CLI exit.

Results preserve stdout, stderr, exit/signal status, observed provider calls,
fingerprints, artifact hashes, wall latency, fixture-marked repeated effects and
interventions. Distinct effect IDs are distinct writes, not duplication: only
repeated observed IDs contribute to repeated_effects. Tool attempts alone do not.
Unknown usage/cost and uninstrumented all-learning activity remain null. The
parent supervisor kills the process group on wall cap and records INCOMPLETE,
never success. A generic child error is not silently converted into a pass.

## Historical offline integration acceptance

The prior integration recorded artifacts under `/tmp/pwn-harness-final-acceptance`.
That temporary path is not a shipped or durable evidence archive. The following
counts describe that historical run, not a rerun of the current checkout or live
provider scores; reproduce the commands above for current acceptance:

- `HOME=/tmp/pwn-harness-final-acceptance/home bundle exec rake`:
  **4369 examples, 0 failures**, then **1150 files, no RuboCop offenses**, exit 0
  (`rake-post-package-fix.log`). The process was awaited through actual exit.
- The focused Loop/runtime/Dispatch/Swarm/verifier/CLI/OpenAI/console/evaluator
  suite: **423 examples, 0 failures**, exit 0 (`focused-post-package-fix.log`).
- `HOME=/tmp/pwn-harness-final-acceptance/home bundle exec rubocop`:
  **1150 files, no offenses**, exit 0 (`rubocop-post-package-fix.log`).
- Historical offline evaluator run (before the RSpec layout migration):
  exit 0. Four baseline tasks PASS; artifact-lie remains FAIL/exit1, and
  timeout-replay remains INCOMPLETE/exit1 with no repeated effect. All five
  executable fault acceptance lanes, eight frozen task/arm trials, five Swarm
  evidence acceptance lanes and two public session-selection lanes passed.
  Negative task outcomes were not relabeled successful work.
- Reusing `offline-final/experiments` as the frozen source via
  `HarnessExperiments.run(output: '/tmp/pwn-harness-final-acceptance/frozen-replay',
  frozen: '/tmp/pwn-harness-final-acceptance/offline-final/experiments')` returned
  exit 0 with equal snapshot digest, schedule, input hashes and graded outcomes.
- Historical packaged acceptance output: `package-verified` beneath the artifact root above.
  Current entry point: `bundle exec rspec spec/integration/harness_package_spec.rb`.
  Its `acceptance.json` is the authority for installed execution and source-byte
  equality, not the earlier source-only counts above.

The initial real evaluator's two Swarm failures, temperature-zero red regression,
cold-gem cap-before-readiness package failure and corrected lint failures remain
in the acceptance ledger rather than being hidden. Natural-language truth requires
authored checks; all live/private model
comparison, quality and superiority claims remain **NOT_RUN**.

## Live comparison protocol — NOT_RUN

`manifest.json` and `adapters.json` have SHA-256 lock files. The runner rejects
manifest drift. Adapter metadata pins the inspected reference source revision
`601b550b4b5addecc0b6dacf9a472a54dd8c6799` and relevant source hashes. It documents
real inspected entry points and constructor fields rather than invented CLI
flags. The reference API is `run_agent.AIAgent(...).run_conversation(...)`.
No reference agent or live provider is launched by the offline evaluator.
`reference_adapter.py` is a separate optional Python-library boundary. It checks
the source revision/hashes and real constructor signature, then invokes the
public API with explicit provider, endpoint, model, reasoning, temperature via
`request_overrides`, toolsets, token/iteration/wall budgets, fresh history, and
disabled context files/memory/background review. It requires `--approve-live`,
an explicitly supplied key, temporary HOME/cwd, a locked same-model parity
manifest, reviewed sandbox/tool parity, and an operator-attested provider-side
hard cost cap. Unknown or unequal provider/model/revision values reject execution.
Raw returned data stays UNVERIFIED until an independent artifact checker grades
it. Aggregate unobserved usage/cost remain null rather than fabricated zeros.

The optional `spec/integration/harness_live_spec.rb` is tagged `:harness_live`
and excluded unless `PWN_TEST_HARNESS_LIVE=1`. It never adds pending examples to
the default gate. Explicit opt-in also requires `PWN_HARNESS_REFERENCE_SOURCE`,
`PWN_HARNESS_LIVE_MANIFEST`, `PWN_HARNESS_PROMPT_FILE`, and `PWN_EVAL_API_KEY`;
missing prerequisites fail rather than skip. The adapter's approval, locked
parity, pinned-source, temporary HOME/cwd and cost-cap checks remain mandatory.
This optional example observes only the reference API response; it does not
establish a paired comparison or model-quality gain. No live lane was run for
the layout migration.

Safe static inspection (does not import the agent or read credentials):

```sh
python3 spec/support/harness/reference_adapter.py --inspect-source /path/to/pinned/reference/source
```

`live_comparison.json` deliberately has unselected provider/model/revision fields
and unapproved budget/parity. It is not runnable until an operator supplies and
locks those choices. Static API validation is not live provider validation or
proof that both providers honor all parity settings on the wire.

Before any comparison, fill and freeze the **same immutable model/version,
reasoning setting, temperature, tools/permissions, task inputs, environment,
iteration/token/wall/cost budget and learned snapshot** for both adapters. These
fields are deliberately unselected, not guessed. Audit equivalent sandbox and
sidecar behavior, instrument all provider calls and billable usage, and enforce
operator-approved cost caps outside both agents. Missing parity means NOT_RUN.

Use paired repeated seeds and randomized arm order. Freeze independently authored
heldout tasks before tuning; these public scripted regression examples are not a
private holdout. Keep raw transcripts and independent artifact checks. Report
success, false-success, repeated effects, interventions, latency and observed
usage/cost, including failures and caps; do not drop incomplete runs. Confidence
intervals and claims of improvement require actual paired live trials.

## Frozen split execution and scoped ablations

`experiments.rb` executes separate train, validation and heldout task identities.
`experiment_tasks.json` and separately authored `experiment_gold.json` are locked
before execution. The checker reads actual bytes; gold is not included in provider
fixtures or task workspaces. Duplicate task IDs, prompts or input bytes across
splits are rejected. This checks explicit leakage, not semantic dataset similarity.
The supplied public corpus and scripted provider are infrastructure regressions,
**not a secret holdout, a live intelligence benchmark, or evidence of learning gains**.

Training uses the real CLI and real Policy paths. After host byte checks succeed,
the real Learning.note_outcome API records a labeled synthetic result without an
invented reward score. The entire isolated training state is copied and frozen
with a per-file hash ledger. Every evaluation trial clones it into a fresh HOME;
no heldout writes flow back into the source snapshot or another trial. The runner
checks the source ledger again after evaluation. Per-trial policy episode counts
exclude episodes inherited from the snapshot. A seeded randomized schedule is
recorded verbatim; reusing a frozen snapshot preserves the input state, not elapsed
times or model randomness.

All offered arms execute real PWN paths:

| Arm | Executed path |
| --- | --- |
| `single-cold` | CLI → Loop, empty HOME, policy disabled |
| `single-snapshot` | CLI → Loop → real learning retrieval, frozen training stores, policy disabled |
| `single-policy` | CLI → Loop → Policy begin/observe/finish, same snapshot, per-trial writes |
| `swarm-snapshot` | CLI → Dispatch agent_spawn/agent_ask → Swarm.ask → nested Loop → real shell; parent readback |

Cold HOME is **not** an all-learning-off switch. The fixture disables automatic
introspection/extrospection in every arm, but ordinary metrics and retrieval are
real. No unimplemented all-learning-off/on arm is offered. Swarm provider calls,
learning-context invocations and policy episodes are observed rather than inferred.
These unequal fixture call counts are wiring evidence, not fair budget-normalized
model superiority. Model quality remains NOT_RUN.

For a diagnostic replay of a previously retained frozen training state, require
`spec/support/harness/experiments` and call `HarnessExperiments.run(output: ...,
frozen: ...)` from Ruby. Use a fresh `/tmp` output directory. This returns raw
observations; the integration specs own acceptance, not a helper's exit status.
Custom locked manifests and gold use the `manifest:` and `gold:` options. They
are trusted local executable fixtures, not untrusted code; the HTTP guard is not
an OS sandbox for arbitrary shell commands. Keep private benchmark gold outside
any live agent sandbox. Do not tune on heldout outcomes.
