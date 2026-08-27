---
name: pwn-plugins-pony
description: Drive PWN::Plugins::Pony from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Pony
  source: pwn/plugins/pony.rb
---

# PWN::Plugins::Pony

This is a fork of the no-longer maintained 'pony' gem. This module's purpose is to exist until the necessary functionality can be integrated into PWN::Plugins::MailAgent

## When to use

Call `PWN::Plugins::Pony` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/pony.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Pony.help
PWN::Plugins::Pony.options(opts)
```

## Public methods

- `options`
- `override_options`
- `subject_prefix`
- `append_inputs`
- `mail`
- `permissable_options`
- `default_delivery_method`
- `standard_options`
- `non_standard_options`
- `build_mail`
- `build_html_part`
- `build_text_part`
- `set_content_type`
- `add_attachments`
- `sendmail_binary`
- `authors`
- `help`
- `options=`
- `override_options=`

## Source

`pwn/plugins/pony.rb`

## Verification

`PWN::Plugins::Pony.respond_to?(:options)` after the
module is loaded. Read the source for parameter names.
