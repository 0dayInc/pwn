---
name: pwn-plugins-hackerone
description: Drive PWN::Plugins::HackerOne from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::HackerOne
  source: pwn/plugins/hacker_one.rb
---

# PWN::Plugins::HackerOne

This plugin is used for interacting w/ HackerOne's Hacker REST API using the 'rest' browser type of PWN::Plugins::TransparentBrowser. Spec: https://api.hackerone.com/getting-started-hacker-api/#getting-started-hacker-api Auth: HTTP Basic on every request (username + API token). Base: https://api.hackerone.com/v1/hackers/ Credentials are sourced from PWN::Env[:plugins][:hackerone]: plugins: hackerone: username: your-h1-username api_key: [set in pwn-vault]

## When to use

Call `PWN::Plugins::HackerOne` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/hacker_one.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::HackerOne.help
PWN::Plugins::HackerOne.login(opts)
```

## Public methods

- `login`
- `api`
- `get_me_reports`
- `get_report`
- `create_report`
- `get_balance`
- `get_earnings`
- `get_payouts`
- `get_programs`
- `get_program`
- `get_structured_scopes`
- `get_scope_exclusions`
- `get_weaknesses`
- `get_hacktivity`
- `get_report_intents`
- `get_report_intent`
- `create_report_intent`
- `update_report_intent`
- `delete_report_intent`
- `submit_report_intent`
- `get_report_intent_attachments`
- `delete_report_intent_attachment`
- `logout`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/hacker_one.rb`

## Verification

`PWN::Plugins::HackerOne.respond_to?(:login)` after the
module is loaded. Read the source for parameter names.
