# Independent local Policy/Registry benchmark

This is a **deterministic controller benchmark, not proof of live LLM improvement**.
It executes real local file tasks and trains the actual tabular
`PWN::AI::Agent::Policy` implementation, then selects actions through the actual
`Registry.rank`. No model responses, provider usage, or benchmark gains are
simulated. The action handlers are explicitly hand-written local algorithms,
not a simulated language model.

## Run from a source checkout

```sh
ruby scripts/benchmark_policy.rb --self-check
ruby scripts/benchmark_policy.rb --output /tmp/pwn-policy-benchmark.json
bundle exec rubocop scripts/benchmark_policy.rb
```

The experiment uses Ruby and its standard libraries; it does not require the
full application boot sequence. Use a fresh Ruby process, not the live agent
console. JSON is printed to stdout and optionally written to `--output`.
`--self-check` runs independent scorer tests, both complete experimental arms,
and two fresh snapshot workers; it prints short pass messages instead of a
report. Use the options separately.
The benchmark exits nonzero if persistence changes during evaluation, splits
overlap, a negative control succeeds, or a positive control fails. Self-checks
also require actual training updates in the on arm and none in the off arm.
They deliberately do **not** require an improvement of a predetermined size.

## Relation to existing evaluation

`lib/pwn/ai/agent/curriculum.rb` provides live self-play, judge-based practice,
mistake-derived evaluation prompts, and adapter training/promotion gates. This
standalone script does not invoke those paths. It provides a small, independently
scored experiment where the training labels come from actual task achievement,
not `Reward.judge`, model prose, or a previously assigned reward. It calls
`Policy.begin_episode`, `observe_step`, and `finish` with those labels during
training. This is not a test of Reward's verification-record binding, the live
Loop, Metrics learning, memory retrieval, or adapter training.

The experimental driver remains in `scripts/`. The opt-in `PolicyEvaluation`
module launches only this fixed runner; it does not load the live agent in its
workers. Its module autoload does not enable evaluation or promotion.

## Protocol

1. **Isolation.** Create a private `/tmp/pwn-policy-benchmark-*` directory. Clear
   the process environment, set `HOME` and `TMPDIR` to that directory, then load
   only Policy and Registry. Assert their persistence constants resolve below
   the temporary `HOME/.pwn`. Do not load user configuration, credentials,
   registered application tools, providers, or network libraries. Delete the
   entire temporary directory on normal completion or Ruby exception and restore
   the process environment. A force-killed process may leave its temporary files.
   This is isolation for trusted fixed handlers, not a sandbox for untrusted code.
2. **Paired arms.** Run `off`, then `on`, resetting Policy between them. Both arms
   start empty and execute the identical training schedule. The only learning
   switch is `PWN::Env[:ai][:agent][:policy]`. No Q entries, visits, episode counts,
   or rewards are seeded directly. Other learning modules are not loaded.
3. **Training only.** There are four training fixtures: two numeric sorting tasks
   and two active-inventory filtering tasks. Six fixed exploration rounds execute
   every one of the three candidate actions for each fixture: 72 real handler
   calls per arm. Every action gets equal exposure; the scheduler does not use
   answer keys to choose actions. Each call writes into a fresh task directory.
   Exact artifact correctness supplies a binary training label to Policy; the
   off arm executes the same work but Policy declines to update.
   Each call has an explicit action ID. Only after the independent artifact
   check, `finish` receives a `controlled_comparison` attribution receipt naming
   that ID. This is a one-action isolated experiment, not a claim that the last
   action in an arbitrary live trace caused the outcome.
4. **Held-out evaluation.** Only after training, materialize eight distinct
   held-out inputs with literal answer keys: four numeric and four inventory
   tasks. Assert no training input appears in evaluation. Task families and
   request wording are intentionally shared with training. The held-out units
   are **input instances, not unseen families, prompts, or tools**. This is
   in-distribution transfer within a small public fixture set, not a blind test
   or a generalization claim about arbitrary operator requests.
5. **Frozen controller.** Rank the task family's three entries using
   `Registry.rank(query: ..., entries: ..., preference: [])`. There are no
   evaluation `begin_episode`, `observe_step`, or `finish` calls. The policy uses
   Registry's normal fallback state rather than a fabricated state/table. Allow
   at most three attempts, stopping only when the independent artifact checker
   passes. The controller does not get corrective feedback or adapt between
   attempts. Hash all persisted `.pwn` files before evaluation and after controls;
   abort if they changed.
6. **Separate controls.** For each held-out input, force a claim-only handler and
   a handler that writes a wrong JSON object. Both return convincing
   `PASS: completed successfully...verified` prose and `ok: true`. All 16 forced
   negative controls must fail objective scoring. Also execute the correct
   algorithm on each input; all eight positive controls must pass. Controls are
   reported separately and never trained on or included in evaluation rates.

## Real task behavior and independent scoring

Numeric candidates perform lexical sorting, numeric sorting, or no artifact
write. Inventory candidates filter active rows, include every row, or write
nothing. Handlers receive only input/output paths; the literal expected values
are not passed to them. All handlers claim success, intentionally making textual
claims unreliable. The checker ignores their prose and action names. It accepts
only a regular non-symlink output whose parsed JSON exactly equals the answer key,
with the source input unchanged. Missing output, invalid JSON, a plausible wrong
artifact, or an altered input is failure. Self-checks separately test missing,
wrong, prose-only, symlink, and correct artifacts.

Each family has equal keyword-fit descriptions, with preference disabled. The
unlearned deterministic tie-break favors lexical sort in one family and the
correct active filter in the other; it is not configured to lose every task.
Lexical sorting can genuinely solve some numeric fixtures and receives credit
when it does. The learned controller can change these tied rankings from
observed outcomes. This construction deliberately isolates the learning-to-router
connection; it does not measure natural-language tool-selection quality.

The answer keys and algorithms live in the same public script but do not call
one another. Independence here means scoring actual artifact/task achievement
without trusting action claims or training rewards, not process-level secrecy or
an external audit. Extending the task set requires reviewing literal answer keys
and adding both positive and negative controls before interpreting new results.

## Report definitions

Each arm contains full training/evaluation traces, fixture inputs and answer keys,
control traces, Policy statistics, persistence fingerprints, and split/freeze
checks. Source hashes identify the Policy, Registry, and harness revisions used.
No fixed gains are embedded in the report.

- **Completion:** tasks with at least one objectively successful attempt divided
  by evaluated tasks. A failed attempt does not count as task completion.
- **Artifact check score:** each attempt earns 1.0 only for an exact correct
  artifact with unchanged input, otherwise 0.0; phase score is its mean across
  attempts. Report rows retain the actual artifact body as well as its hash.
- **False-success count/rate:** attempts claiming `ok: true` without achieving the
  task; rate denominator is executed attempts, not tasks. This is false reporting
  by the handler, not acceptance of that report by the independent checker.
- **Repeated mistakes:** every failed attempt after the first occurrence of the
  same `(family, action, checker failure)` signature within that phase and arm.
  This includes both repeated attempts on one task and recurrence on later
  held-out inputs. It is not the production Mistakes store's count.
- **Calls:** `tool_calls` counts actual local handler invocations. Evaluation makes
  one Registry ranking decision per attempted handler call. Training invokes
  begin/observe/finish once per training call; the returned update reports are
  preserved. Each separately listed control row is one additional handler call.
- **Elapsed:** monotonic measured seconds. Row elapsed time measures the handler;
  phase elapsed time also includes setup, ranking/checking, and training updates
  as applicable. Evaluation phase time excludes separately listed controls;
  top-level elapsed includes both arms and controls but not final JSON output or
  temporary-directory teardown. Tiny timings vary with caching and filesystem
  load; fixed arm order is not a timing-performance study.
- **Cost:** zero LLM calls and zero provider tokens because no provider is invoked.
  Monetary cost is `null` (not estimated), not a claim that local computing is
  economically free. No token-price or electricity estimates are invented.

Training completion is descriptive coverage under forced exploration, not a
learned-policy score. Only the held-out evaluation rates compare the controllers.
Repeated executions should reproduce actions, counts, fixture hashes, and update
counts for the same source revisions. Wall times, temporary paths, timestamps,
and timestamp-bearing persistence hashes are expected to differ.

There is deliberately no external-runner plug-in: accepting arbitrary commands
would undermine the no-network/no-credentials guarantee. A future live-model
study should use a separately reviewed runner, identical model/tool budgets,
external objective verifiers, frozen held-out evaluation, and actual provider
usage records. Do not present this controller experiment as that study.

## Opt-in independent snapshot evaluation (R5)

The original commands and `off`/`on` report shape still work. To additionally
export snapshots and run repeated evaluations in **fresh subprocesses**, use:

```sh
ruby scripts/benchmark_policy.rb --heldout \
  --snapshot-dir /tmp/pwn-policy-snapshots \
  --output /tmp/pwn-policy-heldout.json
```

The snapshot directory must be **new**, below `/tmp`, with no symlink parents.
`off.json` and `on.json` are genuine Policy JSON tables after the same real
training schedule. Exported `updated_at` metadata is normalized to `null` for
reproducible snapshot digests; no Q entries or rewards are fabricated. Export
happens before that arm's evaluation. Neither `--heldout` nor `--snapshot-dir`
promotes anything or discovers/reads a real home-directory policy.

The added `heldout` array contains protocol `pwn-policy-heldout-v2`, for suite
indices 0 and 1. Each worker runs three frozen arms: `off` (baseline snapshot,
policy disabled), `baseline` (baseline enabled), and `candidate` (candidate
enabled). Workers never call begin/observe/finish, warmup, or reset the caller's
policy. Resets and snapshot installation occur only inside temporary HOME.
Only fixed local handlers are registered; no provider, shell tool, credential,
user config, or network client is loaded. Environment variables, including Ruby
startup hooks, are removed before spawning Ruby. Workers have a 30-second
deadline; stalled children are killed and reaped. Snapshot inputs must be regular
non-symlink files, at most 4 MiB, with valid numeric `q`, `h`, `visits`, `returns`,
`n_updates`, and `td_abs_sum` fields. Parent directories cannot be symlinks.

Suite indices 0..7 are bounded deterministic variations, **not random trials**.
Numeric inputs and separate literal answer keys are scaled by `seed + 1`;
inventory IDs and separate answer keys are offset by `100 * seed`. This does not
call a candidate algorithm to construct its answer key. Even indices use flat
paths and compact JSON; odd indices use nested paths containing spaces, pretty
JSON, and read-only inputs. Every arm runs eight tasks, 16 negative controls and
eight positive controls. Training fixtures remain unchanged and disjoint.
These are two task families and two filesystem configurations, not unseen tools
or broad environment generalization. Both environment types are required for
promotion eligibility.
For externally supplied snapshots, `disjoint_inputs` describes the harness's
fixture sets, not proof of the snapshot's training history; that history is not
attested by this runner.

Explicit snapshots from another controlled experiment can be evaluated without
booting the application:

```ruby
require './lib/pwn/ai/agent/policy_evaluation'
evaluator = PWN::AI::Agent::PolicyEvaluation
reports = [0, 1].map do |seed|
  evaluator.evaluate(baseline: '/tmp/baseline.json',
                     candidate: '/tmp/candidate.json', seed: seed)
end
```

With fixed source revisions and snapshot bytes, snapshot reports reproduce all
fields except `elapsed_seconds`. They contain no wall-clock timestamps, random
IDs or temporary paths. The original training report still contains the timing
and metadata variability described above.

## Offline operator CLI

`pwn-ai --policy evaluate|promote|rollback` reuses `PolicyEvaluation`; it never
starts a session, loads the encrypted configuration, runs `Learning.rsi_tick`,
or invokes the agent loop. It cannot be combined with `--ai`, replay, mission,
or other session options. Evaluation accepts existing explicit frozen snapshots,
runs suites 0 and 1, and prints a JSON **array** suitable for `--reports`. It does
not train or write the live policy. The Ruby API supports other indices 0..7.

From a source checkout, this disposable demonstration stays entirely under a
new `/tmp` directory (use `pwn-ai` instead of `ruby -Ilib bin/pwn-ai` for an
installed executable):

```sh
umask 077
work=$(mktemp -d /tmp/pwn-offline-policy.XXXXXX)
ruby scripts/benchmark_policy.rb --heldout \
  --snapshot-dir "$work/snapshots" --output "$work/benchmark.json"
ruby -Ilib bin/pwn-ai --policy evaluate \
  --baseline "$work/snapshots/off.json" --candidate "$work/snapshots/on.json" \
  > "$work/reports.json"
cp "$work/snapshots/off.json" "$work/demo-live.json"
```

Review `reports.json` before deciding whether to proceed. For a real target,
first stop **all** agent processes and other policy writers, take the baseline
copy only after stopping them, and keep writers stopped through promotion and
readback. The acknowledgement does not stop processes or acquire a writer lock.
Concurrent promotions are also unsupported. Do not replace a real policy with
these demonstration snapshots or infer live gains from this fixture experiment.

Only if approving the change to the **disposable demo target**, run:

```sh
ruby -Ilib bin/pwn-ai --policy promote \
  --baseline "$work/snapshots/off.json" --candidate "$work/snapshots/on.json" \
  --reports "$work/reports.json" --live-policy "$work/demo-live.json" \
  --approve-policy-change --policy-writers-stopped > "$work/promotion.json"
cmp "$work/demo-live.json" "$work/snapshots/on.json"
```

The command re-executes both reports before considering replacement. It returns
nonzero on refusal or malformed input; check the exit status and JSON, not just
whether a redirected file exists. Keep the successful `promotion.json` receipt
and digest-named backup. Use distinct, new output paths: shell redirection opens
files before the CLI starts, so never redirect onto snapshots, the live target,
or an existing receipt. A failed retry must not overwrite the successful receipt.

Rollback is a separate explicit operator decision with the same stopped-writer
requirement; it refuses intervening changes to the target:

```sh
ruby -Ilib bin/pwn-ai --policy rollback \
  --receipt "$work/promotion.json" --live-policy "$work/demo-live.json" \
  --approve-policy-change --policy-writers-stopped > "$work/rollback.json"
cmp "$work/demo-live.json" "$work/snapshots/off.json"
```

Neither approval flag alone is sufficient. There is no default live path,
automatic promotion, target discovery, network task, or model training in this
CLI path. Reports and receipts are operator-owned local JSON, not executable
configuration; neither can supply approval flags. Existing `Learning.rsi_tick`
only snapshots measured rates and records a regression lesson. It does not call
this gate, generate candidates, schedule practice, or approve changes. The
broader online learning and curriculum paths remain unchanged and separate.

Focused verification commands (no hardware, providers, or live models):

```sh
bundle exec rspec spec/lib/pwn/ai/cli_spec.rb \
  spec/lib/pwn/ai/agent/policy_evaluation_spec.rb \
  spec/lib/pwn/ai/agent/learning_spec.rb spec/lib/pwn/ai/agent/rsi_metrics_spec.rb
bundle exec rubocop lib/pwn/ai/cli.rb spec/lib/pwn/ai/cli_spec.rb \
  spec/lib/pwn/ai/agent/rsi_metrics_spec.rb
```

## Explicit promotion and rollback

This is an **operator-invoked local eligibility gate**, not automatic online
policy promotion. `Policy.finish` and Loop do not call it. The existing online
learning behavior is not redirected or promoted by this module. No live policy
path is defaulted, and writes require `enabled: true` **and** `quiescent: true`.
The latter is an operator assertion: **stop all agent processes and policy
writers first**. The existing Policy writer does not share a transaction lock
with this module; concurrent live learning or concurrent promotions are not
supported. Restart writers only after the operation and readback complete.

Promotion requires 2..8 reports with distinct valid suite indices covering both
filesystem configurations. It then **reruns each suite in a fresh worker** using
the specified snapshot bytes. Every non-timing report field must match the fresh
execution, including source/harness digests, snapshot digests, input hashes,
artifact bodies and hashes, action choices, scores, controls, and frozen-policy
checks. Hashes alone are not signatures or evidence of trusted authorship;
re-execution is the authority. Model-written `passed: true`, edited scores,
invented artifact bodies, stale source revisions, or copied duplicate reports
cannot substitute for those executions. Supplied elapsed times are discarded;
only newly measured times enter the gate.

For **every** repeated suite, compared with both baseline-on and off:

- completion and mean artifact-check score must not decrease;
- no previously solved individual task may become unsolved (aggregate gains
  cannot hide a task/family regression);
- false-success count **and rate**, repeated mistakes and tool calls must not rise;
- elapsed time must be at most `baseline_seconds * 1.25 + 0.02`, a fixed local
  jitter allowance rather than evidence of a statistically established speedup.

Each suite must also improve completion, false-success count, repeated mistakes,
or calls relative to baseline-on. Better training returns, more updates, or a
timing-only change cannot qualify. The gate fails closed when verification fails.
Snapshots, source digests and live-baseline bytes must still match. An explicit
live target must already exist and equal the evaluated baseline byte-for-byte.
The previous policy is saved beside it as a digest-named rollback JSON before a
same-directory atomic replacement and exact readback. No trajectory file is
modified. Preserve the returned receipt for rollback.

A disposable demonstration using the opt-in benchmark output above:

```ruby
require './lib/pwn/ai/agent/policy_evaluation'
evaluator = PWN::AI::Agent::PolicyEvaluation
baseline = '/tmp/pwn-policy-snapshots/off.json'
candidate = '/tmp/pwn-policy-snapshots/on.json'
reports = JSON.parse(File.read('/tmp/pwn-policy-heldout.json'), symbolize_names: true).fetch(:heldout)
live = '/tmp/pwn-policy-demo-live.json' # NOT the real online policy
File.open(live, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |f| f.write(File.binread(baseline)) }
receipt = evaluator.promote(enabled: true, quiescent: true,
                            baseline: baseline, candidate: candidate,
                            reports: reports, live_path: live)
raise receipt.inspect unless receipt[:promoted]
restored = evaluator.rollback(enabled: true, quiescent: true,
                              live_path: live, receipt: receipt)
raise restored.inspect unless restored[:rolled_back]
```

Rollback verifies the receipt's explicit target, backup path and prior digest,
validates the backup schema, and refuses if the live file no longer matches the
promoted candidate digest. Missing, altered or symlink backups/targets fail
closed. Both methods default to a disabled result; rejected operations return
`promoted: false` or `rolled_back: false` with a reason. `evaluate` raises on an
invalid snapshot, worker failure, or deadline. Force-killing a worker can leave
its temporary directory; this is not an OS sandbox for untrusted code.

**Limit:** this gate measures only the fixed benchmark action vocabulary and
public task families. A real online policy containing unrelated tools may show
no gain and be rejected; passing does not validate those unrelated routes or
establish live LLM gains. A production rollout still needs separately reviewed,
representative objective tasks and operator judgment. Do not interpret this
small public held-out set as a secret test or optimize repeatedly against it
and then claim independent generalization.
