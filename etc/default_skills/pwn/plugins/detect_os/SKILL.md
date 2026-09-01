---
name: pwn-plugins-detectos
description: Drive PWN::Plugins::DetectOS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::DetectOS
  source: pwn/plugins/detect_os.rb
---

# PWN::Plugins::DetectOS

Detect host OS family, distro flavor, and version string.

## When to use

Call `PWN::Plugins::DetectOS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/detect_os.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::DetectOS.help
PWN::Plugins::DetectOS.type(opts)
```

## Public methods

- `type`
- `arch`
- `endian`
- `distro`
- `version`
- `living_off_the_land`
- `authors`
- `help`

## Source

`pwn/plugins/detect_os.rb`

## Verification

`PWN::Plugins::DetectOS.respond_to?(:type)` after the
module is loaded. Read the source for parameter names.
