---
name: pwn-plugins-github
description: Drive PWN::Plugins::Github from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Github
  source: pwn/plugins/github.rb
---

# PWN::Plugins::Github

This plugin is used for interacting w/ Github's REST API using the 'rest' browser type of PWN::Plugins::TransparentBrowser. Credentials are sourced from PWN::Env[:plugins][:github]: plugins: github: username: your-gh-login personal_access_token: [set in pwn-vault] A PAT with `repo` + `workflow` scopes is sufficient for every method here AND for the `gh` CLI (exported as GH_TOKEN by [redacted].gh).

## When to use

Call `PWN::Plugins::Github` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/github.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Github.help
PWN::Plugins::Github.download_all_gists(opts)
```

## Public methods

- `download_all_gists`
- `workflow_runs`
- `workflow_run_jobs`
- `job_log`
- `api`
- `gh`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/github.rb`

## Verification

`PWN::Plugins::Github.respond_to?(:download_all_gists)` after the
module is loaded. Read the source for parameter names.
