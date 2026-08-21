---
name: pwn-plugins-filefu
description: Drive PWN::Plugins::FileFu from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::FileFu
  source: pwn/plugins/file_fu.rb
---

# PWN::Plugins::FileFu

This plugin is primarily used for interacting with files and directories in addition to the capabilities already built within the File and FileUtils built-in ruby classes (e.g. contains an easy to use recursion method that uses yield to interact with each entry on the fly).

## When to use

Call `PWN::Plugins::FileFu` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/file_fu.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::FileFu.help
PWN::Plugins::FileFu.recurse_in_dir(opts)
```

## Public methods

- `recurse_in_dir`
- `untar_gz_file`
- `shift_file_up`
- `authors`
- `help`

## Source

`pwn/plugins/file_fu.rb`

## Verification

`PWN::Plugins::FileFu.respond_to?(:recurse_in_dir)` after the
module is loaded. Read the source for parameter names.
