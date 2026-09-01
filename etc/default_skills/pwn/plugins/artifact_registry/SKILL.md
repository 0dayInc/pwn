---
name: pwn-plugins-artifactregistry
description: Drive PWN::Plugins::ArtifactRegistry from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::ArtifactRegistry
  source: pwn/plugins/artifact_registry.rb
---

# PWN::Plugins::ArtifactRegistry

~/.pwn/artifacts/<session>/ loot index for session_recall.

## When to use

Call `PWN::Plugins::ArtifactRegistry` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/artifact_registry.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::ArtifactRegistry.help
PWN::Plugins::ArtifactRegistry.required_bins(opts)
```

## Public methods

- `required_bins`
- `register`
- `list`
- `get`
- `read_page`
- `authors`
- `help`

## Source

`pwn/plugins/artifact_registry.rb`

## Verification

`PWN::Plugins::ArtifactRegistry.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
