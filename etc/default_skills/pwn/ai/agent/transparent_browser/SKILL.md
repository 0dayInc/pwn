---
name: pwn-ai-agent-transparentbrowser
description: Drive PWN::AI::Agent::TransparentBrowser from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::TransparentBrowser
  source: pwn/ai/agent/transparent_browser.rb
---

# PWN::AI::Agent::TransparentBrowser

This module is an AI agent designed to analyze JavaScript code during a Chrome DevTools debugging session. It generates an Exploit Prediction Scoring System (EPSS) score for each step in the JavaScript code and provides proof-of-concept exploits and code fixes if the score is above a certain threshold.

## When to use

Call `PWN::AI::Agent::TransparentBrowser` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/transparent_browser.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::TransparentBrowser.help
PWN::AI::Agent::TransparentBrowser.analyze(opts)
```

## Public methods

- `analyze`
- `authors`
- `help`

## Source

`pwn/ai/agent/transparent_browser.rb`

## Verification

`PWN::AI::Agent::TransparentBrowser.respond_to?(:analyze)` after the
module is loaded. Read the source for parameter names.
