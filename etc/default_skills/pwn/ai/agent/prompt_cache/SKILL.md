---
name: pwn-ai-agent-promptcache
description: Drive PWN::AI::Agent::PromptCache from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::PromptCache
  source: pwn/ai/agent/prompt_cache.rb
---

# PWN::AI::Agent::PromptCache

agent-style prompt-cache breakpoints. The static system prefix + SKILLS index stay cacheable; dynamic MEMORY / LEARNING / MISTAKES / METRICS / EXTROSPECTION stay uncached so a turn-local write is not baked into the prefix. Anthropic: system is an array of text blocks; the last static block carries cache_control: { type: 'ephemeral' }. OpenAI Chat Completions: two system/developer messages (static then dynamic) plus prompt_cache_key for cache routing. xAI Grok Chat Completions: the same message split plus the x-grok-conv-id request header (sticky server routing). Gemini generateContent: systemInstruction.parts = [static, dynamic] so implicit prefix cache can hit the stable head. Ollama: no-op.

## When to use

Call `PWN::AI::Agent::PromptCache` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/prompt_cache.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::PromptCache.help
PWN::AI::Agent::PromptCache.enabled(opts)
```

## Public methods

- `enabled`
- `split_system`
- `anthropic_system_blocks`
- `openai_messages`
- `gemini_system_instruction`
- `cache_key`
- `cache_marks`
- `supports`
- `authors`
- `help`
- `enabled?`

## Source

`pwn/ai/agent/prompt_cache.rb`

## Verification

`PWN::AI::Agent::PromptCache.respond_to?(:enabled)` after the
module is loaded. Read the source for parameter names.
