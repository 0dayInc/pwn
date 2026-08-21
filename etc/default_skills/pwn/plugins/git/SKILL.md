---
name: pwn-plugins-git
description: Drive PWN::Plugins::Git from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Git
  source: pwn/plugins/git.rb
---

# PWN::Plugins::Git

Used primarily in the past to clone local repos and generate an html diff to be sent via email (deprecated). In the future this plugin may be used to expand upon capabilities required w/ Git.

## When to use

Call `PWN::Plugins::Git` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/git.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Git.help
PWN::Plugins::Git.gen_html_diff(opts)
```

## Public methods

- `gen_html_diff`
- `dump_all_repo_branches`
- `get_author`
- `authors`
- `help`

## Source

`pwn/plugins/git.rb`

## Verification

`PWN::Plugins::Git.respond_to?(:gen_html_diff)` after the
module is loaded. Read the source for parameter names.
