---
name: pwn-plugins-slackclient
description: Drive PWN::Plugins::SlackClient from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::SlackClient
  source: pwn/plugins/slack_client.rb
---

# PWN::Plugins::SlackClient

This plugin is used for interacting w/ Slack over the Web API.

## When to use

Call `PWN::Plugins::SlackClient` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/slack_client.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::SlackClient.help
PWN::Plugins::SlackClient.login(opts)
```

## Public methods

- `login`
- `post_message`
- `logout`
- `authors`
- `help`

## Source

`pwn/plugins/slack_client.rb`

## Verification

`PWN::Plugins::SlackClient.respond_to?(:login)` after the
module is loaded. Read the source for parameter names.
