---
name: pwn-plugins-ttyspinner
description: Drive PWN::Plugins::TTYSpinner from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::TTYSpinner
  source: pwn/plugins/tty_spinner.rb
---

# PWN::Plugins::TTYSpinner

Shared TTY::Spinner lifecycle for REST / AI calls. TTY::Spinner#stop marks @done and Thread#kills the auto_spin worker but does NOT join it. The worker is typically mid-sleep on its interval, so it stays alive long enough to write another frame (cursor col 1 + glyph) over the HTTP response / next PS1. #start owns the worker. #stop joins it. #halt_all! stops every live spinner so a missed ensure cannot leave dots on the TTY.

## When to use

Call `PWN::Plugins::TTYSpinner` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/tty_spinner.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::TTYSpinner.help
PWN::Plugins::TTYSpinner.start(opts)
```

## Public methods

- `start`
- `stop`
- `halt_all`
- `authors`
- `help`
- `halt_all!`

## Source

`pwn/plugins/tty_spinner.rb`

## Verification

`PWN::Plugins::TTYSpinner.respond_to?(:start)` after the
module is loaded. Read the source for parameter names.
