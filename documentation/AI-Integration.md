# AI / LLM Integration — `PWN::AI`

One agent loop, five interchangeable engines. Swap providers by changing one
line in `~/.pwn/config.yml`; the tool-calling contract is normalised so the
agent code never cares which model is behind it.

![Multi-provider integration](diagrams/ai-integration-tool-calling.svg)

## Supported engines

| Engine | Client | Auth | Notes |
|---|---|---|---|
| `openai` | `PWN::AI::OpenAI` | `key:` | function-calling native |
| `anthropic` | `PWN::AI::Anthropic` | `key:` | tool-use native |
| `grok` | `PWN::AI::Grok` | `key:` **or** `oauth: true` | OAuth = RFC-8628 device-code flow using xAI's public Grok-CLI client id (no secret) — see skill `xai_grok_oauth_device_flow` |
| `gemini` | `PWN::AI::Gemini` | `key:` | function-calling native |
| `ollama` | `PWN::AI::Ollama` | none | local, `base_url:` + `model:` |

## Selecting an engine

```yaml
# ~/.pwn/config.yml
ai:
  engine: grok
  grok:
    oauth: true   # first run opens https://accounts.x.ai/… device page
```

```ruby
# at runtime
PWN::Env[:ai][:engine] = :ollama
```

## Direct client use (no agent)

```ruby
resp = PWN::AI::Anthropic.chat(
  messages: [{ role: 'user', content: 'Explain CVE-2024-1234 in one line' }]
)
puts resp[:content]
```

## Model diversity in Swarm

Because each persona in [`agents.yml`](Swarm.md) can override `engine:`, an
`agent_debate` can literally pit Claude against Grok against a local Llama —
real antagonism, not one model role-playing three voices.

**See also:** [pwn-ai Agent](pwn-ai-Agent.md) ·
[Agent Tool Registry](Agent-Tool-Registry.md) · [Swarm](Swarm.md)

[← Home](Home.md)
