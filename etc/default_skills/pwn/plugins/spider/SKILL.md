---
name: pwn-plugins-spider
description: Drive PWN::Plugins::Spider from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Spider
  source: pwn/plugins/spider.rb
---

# PWN::Plugins::Spider

This plugin supports Pastebin actions.

## When to use

Call `PWN::Plugins::Spider` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/spider.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Spider.help
PWN::Plugins::Spider.crawl(opts)
```

## Public methods

- `crawl`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/spider.rb`

## Verification

`PWN::Plugins::Spider.respond_to?(:crawl)` after the
module is loaded. Read the source for parameter names.
