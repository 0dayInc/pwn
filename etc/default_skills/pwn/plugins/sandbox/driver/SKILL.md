---
name: pwnsandboxdriver
description: Drive PWNSandboxDriver from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWNSandboxDriver
  source: pwn/plugins/sandbox/driver.rb
---

# PWNSandboxDriver

Standalone stdlib controller; target execution occurs only in the worker.

## When to use

Call `PWNSandboxDriver` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/sandbox/driver.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWNSandboxDriver.help
PWNSandboxDriver.available?(opts)
```

## Public methods

- `authors`
- `help`
- `available?`
- `bounded`
- `execute`
- `fuzz`
- `inside`
- `main`
- `snapshot`

## Source

`pwn/plugins/sandbox/driver.rb`

## Verification

`PWNSandboxDriver.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
