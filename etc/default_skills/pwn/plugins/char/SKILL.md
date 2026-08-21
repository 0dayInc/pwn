---
name: pwn-plugins-char
description: Drive PWN::Plugins::Char from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Char
  source: pwn/plugins/char.rb
---

# PWN::Plugins::Char

This plugin was created to generate various characters for fuzzing

## When to use

Call `PWN::Plugins::Char` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/char.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Char.help
PWN::Plugins::Char.force_utf8(opts)
```

## Public methods

- `force_utf8`
- `generate_by_range`
- `c0_controls_latin_basic`
- `c1_controls_latin_supplement`
- `latin_extended_a`
- `latin_extended_b`
- `spacing_modifiers`
- `diacritical_marks`
- `greek_coptic`
- `cyrillic_basic`
- `cyrillic_supplement`
- `punctuation`
- `currency_symbols`
- `letterlike_symbols`
- `arrows`
- `math_operators`
- `box_drawings`
- `block_elements`
- `geometric_shapes`
- `misc_symbols`
- `dingbats`
- `bubble_ip`
- `list_encoders`
- `generate_encoded_files`
- `authors`
- `help`

## Source

`pwn/plugins/char.rb`

## Verification

`PWN::Plugins::Char.respond_to?(:force_utf8)` after the
module is loaded. Read the source for parameter names.
