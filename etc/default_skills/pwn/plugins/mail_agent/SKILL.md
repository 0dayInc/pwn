---
name: pwn-plugins-mailagent
description: Drive PWN::Plugins::MailAgent from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::MailAgent
  source: pwn/plugins/mail_agent.rb
---

# PWN::Plugins::MailAgent

This plugin is used for sending email from multiple mail agents such as corporate mail, yahoo, hotmail/live, and mail relays (spoofing). Supports sending multiple file attachments and works pretty well.

## When to use

Call `PWN::Plugins::MailAgent` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/mail_agent.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::MailAgent.help
PWN::Plugins::MailAgent.office365(opts)
```

## Public methods

- `office365`
- `gmail`
- `hotmail_n_live`
- `yahoo`
- `manual`
- `authors`
- `help`

## Source

`pwn/plugins/mail_agent.rb`

## Verification

`PWN::Plugins::MailAgent.respond_to?(:office365)` after the
module is loaded. Read the source for parameter names.
