---
name: pwn-plugins-beef
description: Drive PWN::Plugins::BeEF from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::BeEF
  source: pwn/plugins/beef.rb
---

# PWN::Plugins::BeEF

This plugin is used for interacting w/ BeEF's REST API using the 'rest' browser type of PWN::Plugins::TransparentBrowser.

## When to use

Call `PWN::Plugins::BeEF` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/beef.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::BeEF.help
PWN::Plugins::BeEF.login(opts)
```

## Public methods

- `login`
- `hooks`
- `hooked_browser_info`
- `logs`
- `hooked_browser_logs`
- `modules`
- `module_info`
- `logout`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/beef.rb`

## Verification

`PWN::Plugins::BeEF.respond_to?(:login)` after the
module is loaded. Read the source for parameter names.
