---
name: pwn-json-text
description: Retag binary UTF-8 before JSON.generate so the session pane does not warn.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  module: PWN::JSONText
  source: pwn/json_text.rb
---

# PWN::JSONText

Loaded with `pwn` so `JSON.generate`, `JSON.dump`, and `to_json` retag valid UTF-8 that is still tagged BINARY, and scrub illegal byte sequences. That is what was painting `UTF-8 string passed as BINARY` notices and `JSON::GeneratorError` in the pwn-ai session pane.

## When to use

Do not call this from a task to encode a payload. It is already installed on the JSON generator. Call `PWN::JSONText.prepare` only when a value must be safe before some other encoder.

## How to call

```ruby
PWN::JSONText.help
PWN::JSONText.prepare(value: text)
```
