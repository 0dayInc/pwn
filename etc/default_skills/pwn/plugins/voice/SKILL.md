---
name: pwn-plugins-voice
description: Drive PWN::Plugins::Voice from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Voice
  source: pwn/plugins/voice.rb
---

# PWN::Plugins::Voice

This plugin is used for converting Speech to Text, Text to Speech, and Realtime Voice Mutation

## When to use

Call `PWN::Plugins::Voice` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/voice.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Voice.help
PWN::Plugins::Voice.mutate(opts)
```

## Public methods

- `mutate`
- `speech_to_text`
- `text_to_speech`
- `authors`
- `help`

## Source

`pwn/plugins/voice.rb`

## Verification

`PWN::Plugins::Voice.respond_to?(:mutate)` after the
module is loaded. Read the source for parameter names.
