# Swarm — Native Multi-Agent Orchestration

`PWN::AI::Agent::Swarm` replaces the legacy `pwn-irc` (inspircd + weechat +
PRIVMSG) transport with **first-class sub-agents** built directly on
`PWN::AI::Agent::Loop`. Each persona is a *full* tool-calling agent — Memory,
Skills, Learning, Metrics and Extrospection all apply — so the
self-improvement loop covers the whole swarm.

![Swarm](diagrams/swarm-multi-agent.svg)

## Files

| Path | Contains |
|---|---|
| `~/.pwn/agents.yml` | Persona registry (name → role/engine/toolsets/max_iters) |
| `~/.pwn/swarm/<id>/bus.jsonl` | Append-only chat every persona reads/writes |
| `~/.pwn/swarm/<id>/personas.json` | persona name → `PWN::Sessions` id |

No daemon. Cross-session / cross-process communication == another `pwn-ai` (or
a `PWN::Cron` job) calling `Swarm.ask` with the same `swarm_id`.

## Define personas

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
| `agent_debate(names, topic, rounds:)` | Round-robin critique — each sees the bus tail |
| `agent_broadcast(request)` | Fan-out; returns `{name => reply}` for voting |
| `swarm_bus(swarm_id)` | Tail a bus to inspect a prior/concurrent conversation |
| `swarm_list` | Find a `swarm_id` to resume |


## Escalation persona (local-model circuit-breaker)

`Loop.run` also uses Swarm *implicitly*. When the active engine is `ollama`
and `ai.agent.escalation_persona` names a persona here, the loop counts
in-turn tool failures; once ≥ `Loop::ESCALATE_AFTER_FAILS` (default 4) it
calls `Swarm.ask(name: <persona>, request: "Local agent is stuck on: … Give a
3-line corrective hint")` and injects the reply as a synthetic
`frontier_hint` tool result. The **local model still authors the final
answer** — Learning / Metrics stay attributed to `:ollama`, and every
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
  topic:  'Target runs Jenkins 2.426.2 on :8080 — plan initial access.',
  rounds: 3
)
# later, in a different pwn-ai process:
agent_ask(name: 'red_team', swarm_id: tx[:swarm_id],
          request: 'blue_team raised WAF concerns — revise the payload.')
```

Because each persona can pin a **different engine**, the debate is real model
diversity, not one model role-playing.

**See also:** [pwn-ai Agent](pwn-ai-Agent.md) ·
[Agent Tool Registry](Agent-Tool-Registry.md) · [Sessions](Sessions.md)

[← Home](Home.md)
