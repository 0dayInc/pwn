# Troubleshooting

## SHIFT+ENTER submits instead of newline

`pwn-ai` / `pwn-asm` need the terminal to send a *distinct* code for
Shift-Enter. Under **tmux** both sides must be configured:

```tmux
# ~/.tmux.conf
set -s  extended-keys on
set -as terminal-features 'xterm*:extkeys'   # replace xterm* with your $TERM
```

Then fully **detach and re-attach** (a `source-file` isn't enough for
`terminal-features`). Verify with `tmux display -p '#{client_termfeatures}'`
— it must include `extkeys`.

## `502 Bad Gateway` from a proxy plugin

The upstream (Burp/ZAP) isn't listening. Check:

```bash
ps aux | grep -E 'burp|zap'
ss -tlnp | grep -E ':8080|:1337'
```

Restart via `PWN::Plugins::BurpSuite.start` / `PWN::Plugins::Zaproxy.start` or
fix the port in `~/.pwn/config.yml`.

## `Psych::DisallowedClass` on cron/agents YAML

Fixed in current `PWN::Cron` / `Swarm` — both loaders now pass
`permitted_classes: [Symbol]`. If you see it, `git pull && rake install`.

## Agent stops early ("max iterations")

Raise `ai.agent.max_iters` in `~/.pwn/config.yml`, or split the request.

## A tool is stuck at 0 % success

If you've since fixed the tool, wipe the stale telemetry so it stops steering
the agent away: `metrics_reset(confirm: true)`.

## LLM auth

| Engine | Fix |
|---|---|
| grok `oauth: true` | first run prints a `https://accounts.x.ai/…` URL — open it, approve, token is cached |
| ollama | ensure `ollama serve` is running and `base_url:` matches |
| others | check `key:` under `ai.<engine>` in `~/.pwn/config.yml` |

## Diagrams won't rebuild

`sudo apt install graphviz` (need `dot` on `$PATH`), then
`cd documentation/diagrams && ./build.sh`.

[← Home](Home.md)
