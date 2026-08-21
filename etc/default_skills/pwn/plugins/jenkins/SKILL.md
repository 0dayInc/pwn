---
name: pwn-plugins-jenkins
description: Drive PWN::Plugins::Jenkins from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Jenkins
  source: pwn/plugins/jenkins.rb
---

# PWN::Plugins::Jenkins

This plugin is used to interact w/ the Jenkins API and can be used to carry out tasks when certain events occur w/in Jenkins.

## When to use

Call `PWN::Plugins::Jenkins` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/jenkins.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Jenkins.help
PWN::Plugins::Jenkins.connect(opts)
```

## Public methods

- `connect`
- `create_user`
- `create_ssh_credential`
- `get_all_job_git_repos`
- `list_nested_jobs`
- `list_nested_views`
- `create_nested_view`
- `add_job_to_nested_view`
- `copy_job_no_fail_on_exist`
- `disable_jobs_by_regex`
- `delete_jobs_by_regex`
- `clear_build_queue`
- `disconnect`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/jenkins.rb`

## Verification

`PWN::Plugins::Jenkins.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
