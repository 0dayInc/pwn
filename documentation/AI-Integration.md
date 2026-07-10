# AI / LLM Integration — `PWN::AI`

One agent loop, five interchangeable engines. Swap providers by changing one
line in `~/.pwn/pwn.yaml`; the tool-calling contract is normalised so the
agent code never cares which model is behind it.

![Multi-provider integration](diagrams/ai-integration-tool-calling.svg)

## Supported engines

| Engine | Client | Auth | Notes |
|---|---|---|---|
| `openai` | `PWN::AI::OpenAI` | `key:` | function-calling native |
| `anthropic` | `PWN::AI::Anthropic` | `key:` | tool-use native |
| `grok` | `PWN::AI::Grok` | `key:` **or** `oauth: true` | OAuth = RFC-8628 device-code flow using xAI's public Grok-CLI client id (no secret) — see skill `xai_grok_oauth_device_flow` |
| `gemini` | `PWN::AI::Gemini` | `key:` | function-calling native |
| `ollama` | `PWN::AI::Ollama` | none | local — native `/api/chat` (`num_ctx`, `keep_alive`, low-temp + `format:'json'` on tool turns) and `/api/embed` for `PWN::MemoryIndex` |

> PWN is **model-agnostic**. `ai.<engine>.model` is passed straight through to
> the provider — the codebase and docs deliberately never name a specific
> model id so you can point each engine at whatever the vendor currently
> ships (or whatever `ollama list` shows locally).

## Selecting an engine

```yaml
# ~/.pwn/pwn.yaml
ai:
  active: grok
  grok:
    oauth:
      enroll: true    # first run opens https://accounts.x.ai/… device page
```

```ruby
# at runtime
PWN::Env[:ai][:active] = :ollama
```

## Engine-aware behaviour

The harness adapts to the *class* of engine, not the model name:

| Concern | Frontier (`openai` · `anthropic` · `grok` · `gemini`) | Local (`ollama`) |
|---|---|---|
| **PromptBuilder.budget** | full MEMORY / METRICS / MISTAKES / LEARNING / EXTRO blocks | tightened via `ai.ollama.prompt_budget` (extro off by default) |
| **MEMORY ranking** | relevance-ranked when a local Ollama `embed_model` is reachable, else newest-first | relevance-ranked via `PWN::MemoryIndex` (`~/.pwn/memory.idx`) |
| **Tool schemas shipped** | all toolsets | `CORE_TOOLS` + top-K keyword matches when `ai.agent.tool_router` is on |
| **Pre-pass** | none | `plan_first` numbered tool plan before first dispatch |
| **Few-shot** | none | `Learning.exemplars_for(request)` splices a prior successful trace |
| **Dispatch parsing** | strict | tolerant — Levenshtein tool-name repair + JSON5-ish arg cleanup, each repair fingerprinted into `Mistakes` |
| **Post-answer** | `auto_introspect` | `auto_introspect` **+** `fact_check_local_final` (auto `extro_verify` on CVE/version-shaped claims) |
| **Metrics bucket** | `metrics.json[:tools][name][:engines][:<engine>]` | same — the `TOOL EFFECTIVENESS` block is per-engine so local telemetry never blends with frontier |

## Teacher-student reflection

`ai.reflect_engine` decouples *doing* from *learning-about-doing*:

```yaml
ai:
  active: ollama            # the local model executes tools and answers
  reflect_engine: anthropic # a frontier model writes the durable Memory :lesson
```

`PWN::AI::Agent::Reflect.on` temporarily flips the active engine for the
introspection call only, so the local model reads back distilled reasoning it
could not have produced itself.

## Direct client use (no agent)

```ruby
resp = PWN::AI::Anthropic.chat(
  messages: [{ role: 'user', content: 'Explain CVE-2024-1234 in one line' }]
)
puts resp[:content]
```

## Model diversity in Swarm

Because each persona in [`agents.yml`](Swarm.md) can override `engine:`, an
`agent_debate` can pit five *different providers* against each other — real
antagonism, not one model role-playing three voices. The same mechanism backs
`ai.agent.escalation_persona`: when a local model is stuck, `Loop.run` asks a
frontier persona for a 3-line corrective hint and injects it as a synthetic
tool result.

**See also:** [pwn-ai Agent](pwn-ai-Agent.md) ·
[Agent Tool Registry](Agent-Tool-Registry.md) · [Swarm](Swarm.md) ·
[Configuration](Configuration.md)

[← Home](Home.md)
