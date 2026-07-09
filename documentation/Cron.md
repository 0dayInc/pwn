# Cron — Scheduled Autonomous Jobs

`PWN::Cron` (`lib/pwn/cron.rb`) stores job definitions in
`~/.pwn/cron/jobs.yml` and can install a matching system-`crontab` line that
invokes `PWN::Cron.run(<id>)` on schedule.

![Cron scheduling](diagrams/cron-scheduling.svg)

## Job kinds

| Kind | Executed as | Use for |
|---|---|---|
| `prompt:` | `pwn --ai "<prompt>"` one-shot | "Re-scan scope nightly and diff findings" |
| `ruby:` | `TOPLEVEL_BINDING.eval` in-process | Direct `PWN::Plugins` calls |
| `script:` | `exec` external file | Anything not in Ruby |

## Tools

| Tool | Purpose |
|---|---|
| `cron_create(schedule:, prompt:/ruby:/script:, install_crontab:)` | Define a job |
| `cron_list` | id · name · schedule · enabled · last_run · last_status |
| `cron_run(id:)` | Fire immediately (updates last_run/last_status) |
| `cron_enable` / `cron_disable` | Toggle without deleting |
| `cron_remove` | Delete from `jobs.yml` (does **not** scrub crontab — `crontab -e` yourself) |

## Example

```ruby
cron_create(
  name: 'nightly_scope_sweep',
  schedule: '0 2 * * *',
  prompt: 'extro_snapshot, then NmapIt sweep 10.0.0.0/24, extro_observe every '\
          'new open port, extro_correlate, and post a one-paragraph summary.',
  install_crontab: true
)
```

At 02:00 the system cron fires `PWN::Cron.run`, which spins up a headless
`pwn-ai` turn. With `auto_introspect` on (and optional `auto_extrospect` for
the cheap `AUTO_SECTIONS` baseline), the run updates Learning/Metrics — and,
if enabled, host/repo/env posture — so tomorrow's interactive session already
knows what changed overnight. Sense tools (`intel`/`verify`/`watch`) stay
on-demand; cron is not expected to launch Burp/ZAP/msf/GQRX.

```ruby
cron_create(
  name: 'memory_revalidate',
  schedule: '0 4 * * 0',
  ruby: 'PWN::AI::Agent::Extrospection.revalidate_memory'
)
```

Weekly, headless-browser fact-check of every `PWN::Memory` `:fact` containing
a CVE / version string / URL. Refuted entries get prefixed `[UNVERIFIED
yyyy-mm-dd]` so the injected MEMORY block stops calcifying into
confidently-wrong priors — see [Extrospection § revalidate_memory](Extrospection.md).

**See also:** [Sessions](Sessions.md) · [Extrospection](Extrospection.md) ·
[CLI Drivers](CLI-Drivers.md)

[← Home](Home.md)
