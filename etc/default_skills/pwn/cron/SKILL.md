---
name: pwn-cron
description: Drive PWN::Cron from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Cron
  source: pwn/cron.rb
---

# PWN::Cron

PWN::Cron provides cron / scheduled task management for the pwn-ai agent. Jobs are defined in ~/.pwn/cron/jobs.yml and can be triggered by system cron, manual run, or from within pwn-ai agent loops. Each job can contain a prompt (for pwn-ai), a ruby script snippet, or reference to external script. Delivery can be 'log' (default), 'email', etc. (email would require additional plugins).

## When to use

Call `PWN::Cron` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/cron.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Cron.help
PWN::Cron.cron_dir(opts)
```

## Public methods

- `cron_dir`
- `list`
- `create`
- `run`
- `remove`
- `enable`
- `disable`
- `install_crontab_entry`
- `install_defaults`
- `jobs_file`
- `pid_file`
- `worker_log`
- `due`
- `due_jobs`
- `run_due`
- `worker_status`
- `start_worker`
- `stop_worker`
- `tick`
- `worker_loop`
- `ensure_worker`
- `install_worker_crontab`
- `os_type`
- `windows`
- `scheduler_file`
- `scheduler_config`
- `cron_enabled`
- `persist_scheduler_config`
- `apply_native`
- `which_bin`
- `crontab_available`
- `systemd_user_available`
- `schtasks_available`
- `scheduler_backend`
- `native_unit_dir`
- `ruby_lib_dir`
- `ruby_eval_argv`
- `ruby_eval_shell`
- `cron_to_calendar`
- `systemd_on_calendar`
- `launchd_calendar_interval`
- `schtasks_spec`
- `install_scheduler`
- `uninstall_scheduler`
- `sync_scheduler`
- `scheduler_status`
- `install_native_job`
- `remove_native_job`
- `sync_native_jobs`
- `install_crontab_worker`
- `install_crontab_job`
- `uninstall_crontab`
- `uninstall_crontab_job`
- `install_systemd_user_worker`
- `install_systemd_user_job`
- `uninstall_systemd_user`
- `uninstall_systemd_user_job`
- `install_launchd_worker`
- `install_launchd_job`
- `uninstall_launchd`
- `uninstall_launchd_job`
- `install_schtasks_worker`
- `install_schtasks_job`
- `uninstall_schtasks`
- `uninstall_schtasks_job`
- `authors`
- `help`
- `apply_native?`
- `cron_enabled?`
- `crontab_available?`
- `due?`
- `schtasks_available?`
- `systemd_user_available?`
- `windows?`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/cron.rb`

## Verification

`PWN::Cron.respond_to?(:cron_dir)` after the
module is loaded. Read the source for parameter names.
