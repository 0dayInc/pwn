# Operability and evidence boundaries

This guide connects the documentation to the current source interfaces. A module
or command being present is not proof that its external service, device or model
works on a particular deployment. Examples with targets, credentials or devices
require an operator-configured environment; they are not offline smoke tests.

## Three different feedback paths

| Path | Authority and limit |
| --- | --- |
| Introspection | Metrics, Learning, Mistakes, Reward and Reflect record outcomes and propose corrections. A judge score, stored lesson or tool exit zero is not verified completion. |
| Extrospection | On-demand source observations and optional host/repo/env baselines support diagnosis. Correlation and browser token-overlap checks are fallible, not causal or semantic proof. |
| Living off the land | `DetectOS.living_off_the_land` returns OS metadata and `native` executable names discovered on PATH. PromptBuilder injects its OS summary alongside separate PreflightChecker health. Presence is neither authorization nor successful execution. |

Relevant source: `lib/pwn/plugins/detect_os.rb`,
`lib/pwn/ai/agent/{prompt_builder,extrospection,reward,learning,policy}.rb`.
See [Extrospection](Extrospection.md) and [Introspection](Skills-Memory-Learning.md).

## Completion, regressions and evaluation

The original objective and additive amendments remain authoritative. A generated
plan, exhausted counter, child reply or empty tool-call list cannot independently
establish completion. Exact-target host observations and applicable authored
Verification checks must agree with current artifacts. Checks prove their own
assertions, not every possible interpretation of natural-language intent.

`claimed_completion` preserves the judge's claim; `verified_completion` is
true/false/null for checked pass/failure/unknown. `false_completion_rate` uses
checked claims as its denominator and is null with none. The executable harness
has a different false-success measure: a released success marker is false when
the whole run is not PASS, including empty checks, nonzero exit and resource caps.
Do not combine those denominators or substitute legacy `success_rate`.

Export a regression only from an exact persisted verifier failure and original
request digest, with independently authored expected file/JSON content. The
`Learning.regression_task` recipe is inert acceptance data, not a command replay.
Its split remains `regression`; an inspected failure is not held-out evidence.

Policy evaluation uses explicit frozen baseline/candidate snapshots and fresh
isolated workers. Promotion reruns reports, requires both filesystem environments,
rejects per-task and aggregate regressions, and needs operator approval, stopped
writers and an explicit target. Preserve the versioned receipt and prior bytes.
Rollback refuses intervening writes. This routing-policy gate does not promote
arbitrary skills or model weights and the public fixed local benchmark does not
establish live LLM improvement. See [Harness Evaluation](Harness-Evaluation.md)
and [Policy Benchmark](Policy-Benchmark.md) for exact commands and limits.

## Mesh is a separate transport boundary

`pwn-mesh` uses the selected primary serial/Bluetooth/TCP/MQTT connection;
a configured secondary MQTT receiver is not automatic dual transmission or a
bridge. Eligible `@ai` requests require the dispatch toggle, private channel
and whitelist; replies retain their origin connection and durable session scope.
A local TX header or accepted PhoneAPI write is not RF delivery evidence. MQTT
PKI DMs remain unsupported. Topic `region` is an opaque prefix, not the radio's
regulatory-band setting; `radio_index` is distinct from legacy `channel_num`.
See [General Usage](General-PWN-Usage.md) and [REPL](pwn-REPL.md).

## Deployment and safe verification

1. Inspect the intended checkout and preserve existing changes before upgrading.
   A source edit does not update the activated gem or a running process.
2. Use `/status` or `RuntimeFingerprint.report` to compare loaded source paths and
   observed/current digests. Unknown pre-observer bytes are not a match.
3. Install the reviewed build, restart old processes, and recheck. Keep request
   checkpoints; restoration is not permission to repeat an uncertain mutation.
4. Apply configuration migration only to the intended user state after review.
   A runtime default does not backfill an already-stamped encrypted vault.
5. Run offline gates with installed dependencies and no live integration opt-ins:

```sh
bundle check
bundle exec rspec spec/integration/documentation_sync_spec.rb spec/documentation spec/conventions_spec.rb
bundle exec rake
git diff --check
documentation/diagrams/build.sh
```

The full rake gate includes RSpec, RuboCop and RDoc: await actual exit, not just
an RSpec zero-failure line. Serialize gates in one checkout because RDoc rebuilds
share an output directory. Missing dependencies are a blocked gate, not a pass;
do not weaken the Gemfile to hide them. Optional native/live suites remain
explicit opt-ins documented in [Contributing](Contributing.md).

## Historical assets and scope

`PWN.png` and `pwn_wallpaper.jpg` are branding/artwork. `pwn_install.png`,
`pwn_android_war_dialer_session.png` and `pwn_silent_help_learn_demo.gif` are
historical presentation assets, not current installation or TUI acceptance.
The fax/ringing waveform and spectrogram pairs illustrate recorded signal
shapes; images alone cannot validate current telephony or decoder operation.
They remain preserved rather than being relabeled as newly executed evidence.

The SDR coverage matrix preserves historical per-mode evidence and explicit OPEN
requirements. Current registry enumeration does not close those rows. Native
backends, synthetic fixtures and live RF acceptance must remain separate.

[Home](Home.md) · [Installation](Installation.md) · [Diagrams](Diagrams.md)
