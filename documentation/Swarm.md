# Swarm - Native Multi-Agent Orchestration

`PWN::AI::Agent::Swarm` is first-class multi-agent orchestration built
directly on `PWN::AI::Agent::Loop`. Each persona is a *full* tool-calling agent - Memory,
Skills, Learning, Metrics and Extrospection all apply - so the
self-improvement loop covers the whole swarm.

![Swarm](diagrams/swarm-multi-agent.svg)

## Files

| Path | Contains |
|---|---|
| `~/.pwn/agents.yml` | Persona registry (name → role/engine/model/toolsets/max_iters) |
| `~/.pwn/swarm/<id>/bus.jsonl` | Append-only chat every persona reads/writes |
| `~/.pwn/swarm/<id>/personas.json` | persona name → `PWN::Sessions` id |

No daemon. Cross-session / cross-process communication == another `pwn-ai` (or
a `PWN::Cron` job) calling `Swarm.ask` with the same `swarm_id`.

## Define personas

Each persona accepts optional `engine` and `model` keys. `model` is the exact
provider model identifier (case and punctuation are preserved). Omit `engine`
to inherit the active engine; omit `model` or leave it blank to use the selected
provider's configured default model. Existing engine-only entries still work.

For example, edit `~/.pwn/agents.yml`:

```yaml
reviewer:
  role: Review implementation and tests.
  engine: openai
  model: gpt-6-astra
  toolsets: [terminal, pwn]
local_reviewer:
  role: Independently review implementation and tests.
  engine: ollama
  model: your-installed-model:tag
  toolsets: [terminal, pwn]
```

Replace model identifiers with models available to your configured providers.
Personas can use different models on the same provider or different providers.
The selection applies to `ask`, `debate`, and `broadcast`; overrides are scoped
to each persona execution, restored after nested calls/errors, and do not rewrite
global provider defaults. An omitted model uses the provider default, not an
enclosing persona's model override. Provider authentication is unchanged.

`agent_spawn` also accepts `model:` and `agent_list` reports it.

On upgrade, `pwn setup --migrate` applies schema 3: existing persona entries
without a `model` key receive an unset YAML `model:` field (null, meaning the
selected provider's default). Existing model values, engine selections, and
custom persona fields are preserved. Re-running migration makes no further
changes. A missing `agents.yml` is not created by this migration.

```ruby
agent_spawn(name: 'red_team',
            role: 'Offensive operator. Propose the most aggressive next step.',
            engine: 'grok',
            toolsets: %w[terminal pwn memory skills extrospection])

agent_spawn(name: 'blue_team',
            role: 'Defender. Critique red_team, flag detection risk & OPSEC.',
            engine: 'anthropic',
            toolsets: %w[pwn memory extrospection])
```

> Omit `swarm` from a persona's toolsets to stop it recursively spawning
> further sub-agents. Recursion is also hard-capped by
> `PWN::Env[:ai][:agent][:max_depth]` (default 3).

## Verbs

| Tool | Use for |
|---|---|
| `agent_list` | See who's defined |
| `agent_spawn` | Define / overwrite a persona |
| `agent_ask(name, request)` | One turn of one persona → reply comes back to *you* |
| `agent_debate(names, topic, rounds:)` | Round-robin critique - each sees the bus tail |
| `agent_broadcast(request)` | Fan-out; returns `{name => reply}` for voting |
| `swarm_bus(swarm_id)` | Tail a bus to inspect a prior/concurrent conversation |
| `swarm_list` | Find a `swarm_id` to resume |


## Escalation persona (local-model circuit-breaker)

`Loop.run` also uses Swarm *implicitly*. When the active engine is `ollama`
and `ai.agent.escalation_persona` names a persona here, the loop counts
in-turn tool failures; once ≥ `Loop::ESCALATE_AFTER_FAILS` (default 4) it
calls `Swarm.ask(name: <persona>, request: "Local agent is stuck on: ... Give a
3-line corrective hint")` and injects the reply as a synthetic
`frontier_hint` tool result. The **local model still authors the final
answer** - Learning / Metrics stay attributed to `:ollama`, and every
escalation is fingerprinted into `Mistakes` (tool: `'escalation'`) so
`export_finetune` can later teach the local model to *not* need it.

```yaml
# ~/.pwn/pwn.yaml
ai:
  agent:
    escalation_persona: blue_team   # any persona in ~/.pwn/agents.yml
```

## Example: adversarial exploit review

```ruby
tx = agent_debate(
  names:  %w[red_team blue_team exploit_dev],
  topic:  'Target runs Jenkins 2.426.2 on :8080 - plan initial access.',
  rounds: 3
)
# later, in a different pwn-ai process:
agent_ask(name: 'red_team', swarm_id: tx[:swarm_id],
          request: 'blue_team raised WAF concerns - revise the payload.')
```

Each persona can pin a **different engine and/or model**, rather than requiring
every persona to use one provider's default model.

**See also:** [pwn-ai Agent](pwn-ai-Agent.md) ·
[Agent Tool Registry](Agent-Tool-Registry.md) · [Sessions](Sessions.md)

[← Home](Home.md)
