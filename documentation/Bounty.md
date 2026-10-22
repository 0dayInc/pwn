# `PWN::Bounty` - Bug-Bounty Lifecycle Tooling

| Module | Purpose |
|---|---|
| `PWN::Bounty::LifecycleAuthzReplay` | Plan actor/surface/checkpoint coverage, record caller-supplied observations, and summarize stale-access evidence; it does not automatically replay HAR requests |

Pairs naturally with:

- [`PWN::WWW::HackerOne`](WWW.md) / `BugCrowd` / `Synack` - programme navigation
- `PWN::Plugins::HackerOne` - submissions API
- [`PWN::Plugins::BurpSuite`](BurpSuite.md) - capture the session to replay

```ruby
replay = PWN::Bounty::LifecycleAuthzReplay
plan = replay.load_plan(yaml_path: '/path/to/lifecycle_authz_replay.yaml')
run = replay.start_run(plan: plan, output_dir: '/tmp/authz-evidence')
# Perform the authorized requests separately and record their actual results
# with replay.record_observation(run_obj: run, checkpoint:, actor:, surface:,
#                                status:, request:, response:, artifact_paths:).
summary = replay.finalize_run(run_obj: run)
```

[← Home](Home.md) · [WWW](WWW.md)
