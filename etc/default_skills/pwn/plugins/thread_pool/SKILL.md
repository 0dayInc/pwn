---
name: pwn-plugins-threadpool
description: Drive PWN::Plugins::ThreadPool from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::ThreadPool
  source: pwn/plugins/thread_pool.rb
---

# PWN::Plugins::ThreadPool

This plugin makes the creation of a thread pool much simpler.

## When to use

Call `PWN::Plugins::ThreadPool` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/thread_pool.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::ThreadPool.help
PWN::Plugins::ThreadPool.fill(opts)
```

## Public methods

- `fill`
- `authors`
- `help`

## Source

`pwn/plugins/thread_pool.rb`

## Verification

`PWN::Plugins::ThreadPool.respond_to?(:fill)` after the
module is loaded. Read the source for parameter names.
