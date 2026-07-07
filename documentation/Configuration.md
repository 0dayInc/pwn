# Configuration — `~/.pwn/config.yml`

Everything configurable lives in one YAML file, loaded by `PWN::Config` at
startup and available in-process as `PWN::Env`.

## Minimal example

```yaml
# ~/.pwn/config.yml
ai:
  engine: anthropic          # openai | anthropic | grok | gemini | ollama
  anthropic:
    key: sk-ant-…
  openai:
    key: sk-…
  grok:
    oauth: true              # RFC-8628 device flow, no client_secret
  ollama:
    base_url: http://localhost:11434
    model: llama3.1:70b
  agent:
    max_iters:      40       # tool-loop cap per turn
    max_depth:      3        # swarm recursion cap
    auto_reflect:   true     # Learning.auto_reflect after every final answer
    auto_extrospect: true    # Extrospection.auto_extrospect likewise

burp:
  jar: /opt/burpsuite_pro/burpsuite_pro.jar
  api_key: …

metasploit:
  host: 127.0.0.1
  port: 55553
  user: msf
  pass: …
```

## Reading / writing at runtime

```ruby
PWN::Env[:ai][:engine]                 # => :anthropic
PWN::Env[:ai][:agent][:auto_reflect]   # => true
PWN::Config.reload!
```

## Sections PWN looks for

| Key path | Consumed by |
|---|---|
| `ai.engine` | `PWN::AI::Agent::Loop` — which client to instantiate |
| `ai.<engine>.key` / `.oauth` | `PWN::AI::OpenAI` / `Anthropic` / `Grok` / `Gemini` / `Ollama` |
| `ai.agent.max_iters` | hard stop on tool-call rounds |
| `ai.agent.max_depth` | `Swarm` recursion guard |
| `ai.agent.auto_reflect` | toggle `Learning.auto_reflect` |
| `ai.agent.auto_extrospect` | toggle `Extrospection.auto_extrospect` |
| `burp.*` | `PWN::Plugins::BurpSuite` |
| `metasploit.*` | `PWN::Plugins::Metasploit` |
| `zap.*` | `PWN::Plugins::Zaproxy` |
| `shodan.key` / `hunter.key` / … | respective OSINT plugins |
| `aws.*` | `PWN::AWS::*` (falls back to standard AWS SDK env/instance-profile) |

## Other files under `~/.pwn/`

See [Persistence](Persistence.md) for the full map.

[← Home](Home.md)
