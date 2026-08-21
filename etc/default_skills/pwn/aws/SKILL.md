---
name: pwn-aws
description: Drive PWN::AWS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS
  source: pwn/aws.rb
---

# PWN::AWS

This file, using the autoload directive loads AWS modules into memory only when they're needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html

## When to use

Call `PWN::AWS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS.help
PWN::AWS.help(opts)
```

## Public methods

- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/aws.rb`

## Verification

`PWN::AWS.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
