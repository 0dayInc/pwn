# Configuration — `~/.pwn/pwn.yaml`

Everything configurable in PWN lives in **one encrypted YAML file**, loaded by
`PWN::Config.refresh_env` at driver startup and exposed in-process as the
frozen constant **`PWN::Env`** (a redacted copy is available as
`PWN::EnvRedacted`).

The file is **AES-encrypted at rest** by `PWN::Plugins::Vault`. Its key/IV
live in a sibling **`~/.pwn/pwn.yaml.decryptor`** file (or in
`PWN_DECRYPTOR_KEY` / `PWN_DECRYPTOR_IV` env vars). Never edit `pwn.yaml`
by hand — use the **`pwn-vault`** REPL command, which decrypts → opens
`$EDITOR` → re-encrypts → reloads `PWN::Env`.

If `~/.pwn/pwn.yaml` does not exist on first run, `PWN::Config.default_env`
writes a fully-commented template with every key below (values set to
`'optional - …'` / `'required - …'` placeholder strings), encrypts it, and
generates the decryptor.

> **Before configuring**, run `pwn setup` — the
> [doctor](Installation.md#pwn-setup--the-post-install-doctor--provisioner)
> reports whether `~/.pwn/`, `pwn.yaml`, its decryptor, and an AI-engine key
> are present, and exits non-zero for CI if any are missing.

---

## Full annotated example

```yaml
# ~/.pwn/pwn.yaml  (shown DECRYPTED — file is AES-encrypted on disk)

ai:
  active: grok                     # Which engine backs `pwn-ai`. One of: openai | anthropic | grok | gemini | ollama.
  module_reflection: false         # Master gate for LLM self-analysis (SAST triage, Burp enrichment, Learning.llm_reflect).

  grok:
    base_uri: https://api.x.ai/v1  # xAI API base URL. Override for a self-hosted proxy / private endpoint.
    key: xai-…                     # xAI API key. If blank AND no oauth.* below, PWN prompts interactively at load.
    model: <model-id>              # Model id sent on every chat / tool-loop request. See provider docs / API for currently-supported ids.
    system_role_content: 'You are an ethically hacking xAI Grok agent.'   # Base system prompt (MEMORY/SKILLS/LEARNING/EXTROSPECTION blocks are appended to this).
    temp: 1.0                      # Sampling temperature passed to the chat endpoint.
    max_prompt_length: 256000      # Soft input-context ceiling (chars) used for prompt truncation / chunking.
    oauth:                         # RFC-8628 device-flow (SuperGrok subscription) — public client, no client_secret.
      refresh_token: ~             # Durable OAuth refresh token; enables silent re-auth without an API key.
      bearer_token: ~              # Short-lived OAuth access JWT; auto-refreshed each run when refresh_token is set.
      client_id: b1a00492-073a-47ea-816f-4c329264a828   # xAI's PUBLIC OAuth client id for the "Grok CLI" application (not sensitive).
      client_secret: ~             # Only for confidential-client OAuth flows; unused by the public Grok-CLI client.
      scope: 'openid profile email offline_access grok-cli:access api:access'   # OAuth scope string requested during device-flow enrollment.
      token_uri: https://auth.x.ai/oauth2/token          # OAuth token endpoint (override for enterprise IdP).
      enroll: false                # true → force RFC-8628 device-flow enrollment on load even when `key:` is set.

  openai:
    base_uri: https://api.openai.com/v1   # OpenAI API base URL. Override for Azure OpenAI / VPC gateway / local proxy.
    key: sk-…                             # OpenAI API key (`sk-…`). Prompted interactively if blank.
    model: <model-id>                     # Model id sent on every chat / tool-loop request. See provider docs / API for currently-supported ids.
    system_role_content: 'You are an ethically hacking OpenAI agent.'   # Base system prompt for this engine.
    temp: 1.0                             # Sampling temperature.
    max_prompt_length: 128000             # Soft input-context ceiling (chars) for truncation / chunking.
    max_tokens: 16384                     # Max OUTPUT tokens per response. Mapped to OpenAI wire param `max_completion_tokens`.

  anthropic:
    base_uri: https://api.anthropic.com/v1   # Anthropic API base URL. Override for Bedrock / private gateway.
    key: sk-ant-…                            # Anthropic API key (`sk-ant-…`). Prompted interactively if blank.
    model: <model-id>                        # Model id sent on every chat / tool-loop request. See provider docs / API for currently-supported ids.
    system_role_content: 'You are an ethically hacking Anthropic agent.'   # Base system prompt for this engine.
    temp: 1.0                                # Sampling temperature.
    max_tokens: 8192                         # Max OUTPUT tokens per response. Raise if tool-call JSON truncates.
    max_prompt_length: 200000                # Soft input-context ceiling (chars) for truncation / chunking.

  gemini:
    base_uri: https://generativelanguage.googleapis.com/v1beta   # Google Generative Language API base URL.
    key: AIza…                               # Google AI Studio API key (`AIza…`). Prompted interactively if blank.
    model: <model-id>                        # Model id sent on every chat / tool-loop request. See provider docs / API for currently-supported ids.
    system_role_content: 'You are an ethically hacking Gemini agent.'   # Base system prompt for this engine.
    temp: 1.0                                # Sampling temperature.
    max_prompt_length: 1000000               # Soft input-context ceiling (chars) — Gemini supports very large contexts.

  ollama:
    base_uri: https://ollama.local           # REQUIRED for ollama — Open WebUI / ollama-serve base URL (no vendor default).
    key: eyJ…                                # Open WebUI JWT (Settings → Account → API Key). Prompted if blank.
    model: <local-model-tag>                 # Local model tag exactly as `ollama list` shows it.
    embed_model: <embed-model-tag>           # Embedding model for PWN::MemoryIndex (relevance-ranked MEMORY). Must be pulled locally.
    system_role_content: 'You are an ethically hacking Ollama agent.'   # Base system prompt for this engine.
    temp: 1.0                                # Sampling temperature (used on the FINAL text-only turn — tool-bearing turns are pinned low for deterministic routing).
    num_ctx: 32768                           # Context window passed to /api/chat options.num_ctx. Ollama's default (2048) is too small for the pwn-ai system prompt.
    keep_alive: 30m                          # How long ollama keeps the model resident between iterations (avoids reload latency mid-turn).
    prompt_budget:                           # Per-block caps applied by PromptBuilder.budget so a small model spends attention on the request, not the harness.
      memory: 6                              # Max MEMORY entries injected (relevance-ranked via PWN::MemoryIndex when available).
      metrics: 3                             # Max TOOL EFFECTIVENESS rows.
      mistakes: 3                            # Max KNOWN MISTAKES / FIXES rows.
      learning: 2                            # Max recent LEARNING outcomes shown.
      extro: false                           # Gate the (heaviest) EXTROSPECTION block entirely for local models.
    max_prompt_length: 32000                 # Soft input-context ceiling (chars) — tune per local model's real context window.

  reflect_engine: ~                # Teacher-student reflection: EXECUTE on ai.active, but write durable lessons via THIS engine (nil = same as active). Lets a local model act while a frontier model authors the Memory :lesson entries it reads back.

  agent:
    native_tools: true             # Use provider-native tool_calls / function-calling. false → legacy text-parsed tool protocol.
    max_iters: 25                  # Hard cap on tool-call rounds per user turn before a forced final answer.
    max_depth: 3                   # Recursion guard: how many levels deep agent_ask/agent_debate sub-agents may spawn sub-agents.
    auto_introspect: true          # Run Learning.auto_introspect (outcome logging + lesson mining) after every final answer.
    auto_extrospect: false         # Optional ambient baseline (host/repo/env ONLY — never launches burpsuite/zaproxy/msf/gqrx). Sense tools (intel/verify/watch/rf_tune/observe) stay on-demand.
    plan_first: ~                  # Plan-then-act pre-pass: force the model to externalise a numbered tool plan BEFORE its first dispatch. nil = auto (true when ai.active == ollama).
    tool_router: false             # Dynamic tool-set slimming: ship only Registry::CORE_TOOLS + top-K keyword-relevant schemas per turn (helps small models route correctly).
    escalation_persona: ~          # Swarm persona name to ask for a 3-line corrective hint once a local model burns ≥ Loop::ESCALATE_AFTER_FAILS in-turn failures. nil = disabled.
    toolsets: ~                    # Allow-list of toolsets exposed to the agent. nil = all. Valid: cron, extrospection, learning, memory, metrics, pwn, sessions, skills, swarm, terminal.
    extrospection:
      web:
        anchors:                   # URLs the headless browser fingerprints on extro_snapshot(sections:[:web]). Alias: web_anchors.
          - https://nvd.nist.gov
          - https://www.exploit-db.com
        proxy: ~                   # Upstream proxy for TransparentBrowser during probe_web/verify/watch (e.g. 'tor', http://127.0.0.1:8080).
        max_anchors: 8             # Cap on how many anchors are rendered per snapshot (protects run time).
        per_page_timeout: 15       # Seconds before a single page render is abandoned and recorded as unreachable.
        screenshot: false          # Persist a PNG per anchor to ~/.pwn/extrospection/web/ (disk-heavy; off by default).
        allow_targets: false       # true → also merge top-level `targets:` into anchors (opt-in — off so in-scope hosts aren't touched unprompted).
      rf:
        host: 127.0.0.1            # GQRX remote-control host for extro_rf_tune.
        port: 7356                 # GQRX remote-control port.
        settle_secs: 8             # Seconds to sample RDS after tuning (max 30).
        ttl: 300                   # Observation TTL for :rf (songs change — keep short).

plugins:
  asm:
    arch: x86_64                   # Target architecture for `pwn-asm` inline assembler/disassembler. Default: PWN::Plugins::DetectOS.arch.
    endian: little                 # Endianness for `pwn-asm` (little | big). Default: PWN::Plugins::DetectOS.endian.
  blockchain:
    bitcoin:
      rpc_host: localhost          # bitcoind JSON-RPC host for PWN::Blockchain::BTC.
      rpc_port: 8332               # bitcoind JSON-RPC port.
      rpc_user: …                  # bitcoind RPC username (rpcauth / rpcuser in bitcoin.conf).
      rpc_pass: …                  # bitcoind RPC password. Redacted in PWN::EnvRedacted.
  hunter:
    api_key: …                     # hunter.how API key — passed as api_key: to PWN::Plugins::Hunter.search.
  jira_data_center:
    base_uri: https://jira.company.com/rest/api/latest   # Jira Data Center REST base URL.
    token: …                       # Jira Personal Access Token for PWN::Plugins::JiraDataCenter. Redacted.
  meshtastic:
    admin_key: …                   # Public key authorised to send admin messages to mesh nodes via `pwn-mesh`.
    serial:
      port: /dev/ttyUSB0           # Serial device path for a locally-attached Meshtastic node.
      baud: 115200                 # Serial baud rate.
      bits: 8                      # Serial data bits.
      stop: 1                      # Serial stop bits.
      parity: none                 # Serial parity (none | even | odd).
    mqtt:
      host: mqtt.meshtastic.org    # MQTT broker hostname for Meshtastic-over-MQTT.
      port: 1883                   # MQTT broker port (8883 for TLS).
      tls: false                   # Use TLS to the MQTT broker.
      user: meshdev                # MQTT username (public Meshtastic broker default shown).
      pass: large4cats             # MQTT password (public Meshtastic broker default shown). Redacted.
    channel:
      active: LongFast             # Which named channel block below `pwn-mesh` uses for TX/RX.
      LongFast:                    # Channel definition — name is arbitrary, referenced by `active:` above.
        psk: 'AQ=='                # Channel pre-shared key (base64). 'AQ==' = Meshtastic default public key. Redacted.
        region: US/UT              # LoRa region tag (regulatory band).
        topic: 2/e/#               # MQTT topic filter to subscribe/publish for this channel.
        channel_num: 8             # Meshtastic channel index (slot number on the device).
        from: '!deadbeef'          # Sender node id used on outbound packets. Optional — defaults to !<mqtt client_id>.
      PWN:                         # Example second (private) channel definition.
        psk: …                     # Private channel pre-shared key (base64). Redacted.
        region: US/UT              # LoRa region tag for this channel.
        topic: 2/e/PWN/#           # MQTT topic filter for this channel.
        channel_num: 99            # Meshtastic channel index for this channel.
  shodan:
    api_key: …                     # Shodan API key — passed as api_key: to PWN::Plugins::Shodan.*. Redacted.

memory:
  enabled: true                    # Reserve — persistent-memory subsystem on/off (currently always active; future gate).
  provider: file                   # Storage backend for PWN::Memory: file (~/.pwn/memory.json). `sqlite` reserved.

sessions:
  enabled: true                    # Reserve — transcript recording on/off (currently always active; future gate).
  provider: jsonl                  # Transcript format under ~/.pwn/sessions/ (one .jsonl per session).

cron:
  enabled: true                    # Reserve — scheduled-job subsystem on/off (currently always active; future gate).
  provider: yaml                   # Job store format for PWN::Cron (~/.pwn/cron/jobs.yml).

targets:                           # Optional — engagement-scope URLs/hosts. Merged into :web snapshot anchors
  - https://target.example.com     #   ONLY when ai.agent.extrospection.web.allow_targets: true.
| `ai.agent.extrospection.rf.host` | String | `127.0.0.1` | `Extrospection.rf_tune` | GQRX remote-control host for the RF sense organ. |
| `ai.agent.extrospection.rf.port` | Integer | `7356` | `Extrospection.rf_tune` | GQRX remote-control port. |
| `ai.agent.extrospection.rf.settle_secs` | Integer | `8` | `Extrospection.rf_tune` | Seconds to sample RDS after tuning (capped at 30). |
| `ai.agent.extrospection.rf.ttl` | Integer | `300` | `Extrospection.rf_tune` | TTL (seconds) for `:rf` observations written by `extro_rf_tune` (ephemeral radio content). |
```

---

## Reading / writing at runtime

```ruby
PWN::Env[:ai][:active]                          # => :grok
PWN::Env.dig(:ai, :agent, :max_iters)           # => 25
PWN::EnvRedacted[:ai][:grok][:key]              # => ">>> REDACTED >>> …"

# Edit + re-encrypt + reload without leaving the REPL:
pwn-vault

# Force a reload from disk (e.g. after pwn-vault in another shell):
PWN::Config.refresh_env
```

---

## Exhaustive key reference

### `ai` — AI engines & agent loop

| Key path | Type | Default | Consumed by | Purpose |
|---|---|---|---|---|
| `ai.active` | String | `grok` | `PWN::Config.refresh_env`, `PWN::AI::Agent::Loop`, `PWN::Plugins::REPL`, `PWN::Cron` | Which AI engine backs `pwn-ai`. One of `openai` · `anthropic` · `grok` · `gemini` · `ollama`. |
| `ai.module_reflection` | Boolean | `false` | `PWN::AI::Agent::Reflect`, `PWN::SAST::*`, `PWN::Plugins::BurpSuite` | Master gate for LLM-driven self-analysis (SAST triage, Burp finding enrichment, `Learning.llm_reflect`). |
| `ai.<engine>.base_uri` | String | provider default | `PWN::AI::<Engine>.rest_call` | Override the API base URL (self-hosted proxy, private endpoint, Azure/VPC gateway). **Required** for `ollama`. |
| `ai.<engine>.key` | String | — | `PWN::AI::<Engine>` | API key / bearer token. If blank AND no OAuth is configured, PWN prompts interactively at load. |
| `ai.<engine>.model` | String | provider default | `PWN::AI::<Engine>.chat` / `.chat_tool_loop` | Model id sent on every request. Use whatever id the provider / `ollama list` currently exposes — PWN never hard-codes a specific model. |
| `ai.<engine>.system_role_content` | String | ethical-hacker persona | `PWN::AI::Agent::PromptBuilder`, `PWN::Plugins::REPL` | Base system prompt prepended to MEMORY / SKILLS / LEARNING / EXTROSPECTION blocks. |
| `ai.<engine>.temp` | Float | `1.0` | `PWN::AI::<Engine>.chat` | Sampling temperature. |
| `ai.<engine>.max_prompt_length` | Integer | per-engine | `PWN::AI::<Engine>`, `PWN::Plugins::REPL` | Soft input-context ceiling used for prompt truncation / chunking. |
| `ai.anthropic.max_tokens` | Integer | `8192` | `PWN::AI::Anthropic.chat_tool_loop` | Max **output** tokens per response. Raise if tool-call JSON truncates. |
| `ai.openai.max_tokens` | Integer | `16384` | `PWN::AI::OpenAI.chat` | Max **output** tokens per response. Mapped to OpenAI's wire param `max_completion_tokens` (legacy env key `max_completion_tokens` still accepted). |
| `ai.ollama.embed_model` | String | provider default | `PWN::MemoryIndex` | Local embedding model tag used to build `~/.pwn/memory.idx` for **relevance-ranked** MEMORY injection. Falls back to substring recall when unset / unreachable. |
| `ai.ollama.num_ctx` | Integer | `32768` | `PWN::AI::Ollama.chat_with_tools` | Context window sent as `options.num_ctx` on the native `/api/chat` call. Ollama's own default (2048) truncates the pwn-ai system prompt. |
| `ai.ollama.keep_alive` | String | `30m` | `PWN::AI::Ollama.chat_with_tools` | How long the model stays resident in ollama between iterations of a single turn. |
| `ai.ollama.prompt_budget` | Hash | `{memory:6, metrics:3, mistakes:3, learning:2, extro:false}` | `PWN::AI::Agent::PromptBuilder.budget` | Per-block caps on injected context so a small local model spends its attention on the request, not the harness. Any engine may set this. |
| `ai.reflect_engine` | Symbol \| `nil` | `nil` (= `ai.active`) | `PWN::AI::Agent::Reflect.on`, `Learning.reflect` | **Teacher-student** override: run the task on `ai.active`, but generate durable lessons via *this* engine. Lets a local model execute while a frontier model writes the Memory it reads back. |
| `ai.grok.oauth.refresh_token` | String | — | `PWN::AI::Grok.resolve_auth` | Durable OAuth refresh token (from `PWN::AI::Grok.obtain_oauth_bearer_token` device flow). Enables silent re-auth without an API key. |
| `ai.grok.oauth.bearer_token` | String | — | `PWN::AI::Grok.resolve_auth` | Short-lived OAuth access JWT. Auto-refreshed each run when `refresh_token` is present; live-cached back into this hash. |
| `ai.grok.oauth.client_id` | String | Grok-CLI public id | `PWN::AI::Grok` | Override the public OAuth client id used for device-flow / refresh. |
| `ai.grok.oauth.client_secret` | String | — | `PWN::Config.refresh_env`, `PWN::AI::Grok` | Only for confidential-client OAuth flows. Unused by the default public Grok-CLI client. |
| `ai.grok.oauth.scope` | String | see example | `PWN::AI::Grok` | OAuth scope string requested during device-flow enrollment. |
| `ai.grok.oauth.token_uri` | String | `https://auth.x.ai/oauth2/token` | `PWN::AI::Grok` | OAuth token endpoint (override for enterprise IdP). |
| `ai.grok.oauth.enroll` | Boolean | `false` | `PWN::AI::Grok` | `true` → always run RFC-8628 device-flow enrollment on load, even when `ai.grok.key` is set. |

### `ai.agent` — pwn-ai autonomous loop

| Key path | Type | Default | Consumed by | Purpose |
|---|---|---|---|---|
| `ai.agent.native_tools` | Boolean | `true` | `PWN::Plugins::REPL` (`pwn-ai` cmd) | Use provider-native `tool_calls` / function-calling. `false` falls back to the legacy text-parsed tool protocol. |
| `ai.agent.max_iters` | Integer | `25` | `PWN::AI::Agent::Loop.run`, `PWN::AI::Agent::Swarm` | Hard cap on tool-call rounds per user turn before a forced final answer. |
| `ai.agent.max_depth` | Integer | `3` | `PWN::AI::Agent::Swarm` | Recursion guard for `agent_ask` / `agent_debate` sub-agents spawning sub-agents. |
| `ai.agent.auto_introspect` | Boolean | `true` | `PWN::AI::Agent::Learning.auto_introspect` | Run outcome logging + lesson mining after every final answer. Toggle live via `learning_auto_introspect_toggle`. |
| `ai.agent.auto_extrospect` | Boolean | `false` | `PWN::AI::Agent::Extrospection.auto_extrospect` | Optional ambient baseline after every final answer (`AUTO_SECTIONS` = host/repo/env only; never spawns GUI/JVM tools). Prefer on-demand sense tools (`intel`/`verify`/`watch`/`rf_tune`/`observe`). Toggle live via `extro_auto_toggle`. |
| `ai.agent.toolsets` | Array\<String\> \| `nil` | `nil` (all) | `bin/pwn`, `PWN::Plugins::REPL`, `PWN::AI::Agent::Registry` | Allow-list of toolsets exposed to the agent. Valid: `cron`, `extrospection`, `learning`, `memory`, `metrics`, `pwn`, `sessions`, `skills`, `swarm`, `terminal`. |
| `ai.agent.plan_first` | Boolean \| `nil` | `nil` (auto: `true` when `ai.active == ollama`) | `PWN::AI::Agent::Loop.plan_first` | Plan-then-act pre-pass: the model must emit a numbered tool plan (as an assistant message) *before* it may dispatch anything. Cheap chain-of-thought scaffolding for local models. |
| `ai.agent.tool_router` | Boolean | `false` | `PWN::AI::Agent::Registry.definitions` | Dynamic tool-set slimming: expose only `Registry::CORE_TOOLS` + the top-K keyword-relevant schemas for *this* request. Ties break on historical `Metrics` success rate so the router itself is a learned component. |
| `ai.agent.escalation_persona` | String \| `nil` | `nil` | `PWN::AI::Agent::Loop.escalate` → `Swarm.ask` | Circuit-breaker: once a local model accumulates ≥ `Loop::ESCALATE_AFTER_FAILS` in-turn failures, ask this Swarm persona for a 3-line corrective hint (injected as a synthetic tool result). The local model still authors the final answer so Learning/Metrics stay attributed. |
| `ai.agent.extrospection.web.anchors` | Array\<String\> | `DEFAULT_WEB_ANCHORS` | `PWN::AI::Agent::Extrospection.probe_web` | URLs the headless browser fingerprints on `extro_snapshot(sections:[:web])`. Alias: `web_anchors`. |
| `ai.agent.extrospection.web.proxy` | String | — | `Extrospection.probe_web` / `.verify` / `.watch` | Upstream proxy for `PWN::Plugins::TransparentBrowser` (e.g. `tor`, `http://127.0.0.1:8080`). |
| `ai.agent.extrospection.web.max_anchors` | Integer | `8` | `Extrospection.probe_web` | Cap on anchors rendered per snapshot. |
| `ai.agent.extrospection.web.per_page_timeout` | Integer | `15` | `Extrospection` (headless browser) | Seconds before a page render is abandoned. |
| `ai.agent.extrospection.web.screenshot` | Boolean | `false` | `Extrospection.probe_web` / `.watch` | Persist a PNG per anchor to `~/.pwn/extrospection/web/`. |
| `ai.agent.extrospection.web.allow_targets` | Boolean | `false` | `Extrospection.web_anchors` | Merge top-level `targets:` into the anchor list (opt-in — off by default to avoid touching in-scope hosts unprompted). |

### `plugins` — module credentials & wiring

| Key path | Type | Default | Consumed by | Purpose |
|---|---|---|---|---|
| `plugins.asm.arch` | String | `DetectOS.arch` | `PWN::Plugins::REPL` (`pwn-asm`) | Target architecture for the inline assembler / disassembler prompt (`x86_64`, `arm64`, …). |
| `plugins.asm.endian` | String | `DetectOS.endian` | `PWN::Plugins::REPL` (`pwn-asm`) | Endianness for the inline assembler (`little` / `big`). |
| `plugins.blockchain.bitcoin.rpc_host` | String | `localhost` | `PWN::Blockchain::BTC` | bitcoind JSON-RPC host. |
| `plugins.blockchain.bitcoin.rpc_port` | Integer | `8332` | `PWN::Blockchain::BTC` | bitcoind JSON-RPC port. |
| `plugins.blockchain.bitcoin.rpc_user` | String | — | `PWN::Blockchain::BTC` | bitcoind RPC username. |
| `plugins.blockchain.bitcoin.rpc_pass` | String | — | `PWN::Blockchain::BTC` | bitcoind RPC password. |
| `plugins.hunter.api_key` | String | — | `PWN::Plugins::Hunter` | hunter.how API key (passed as `api_key:` to `Hunter.search`). |
| `plugins.jira_data_center.base_uri` | String | — | `PWN::Plugins::JiraDataCenter` | Jira DC REST base (e.g. `https://jira.company.com/rest/api/latest`). |
| `plugins.jira_data_center.token` | String | — | `PWN::Plugins::JiraDataCenter` | Jira Personal Access Token. |
| `plugins.meshtastic.admin_key` | String | — | `PWN::Plugins::REPL` (`pwn-mesh`) | Public key authorised to send admin messages to mesh nodes. |
| `plugins.meshtastic.serial.port` | String | `/dev/ttyUSB0` | `pwn-mesh` (serial) | Serial device path for a locally-attached Meshtastic node. |
| `plugins.meshtastic.serial.baud` | Integer | `115200` | `pwn-mesh` (serial) | Serial baud rate. |
| `plugins.meshtastic.serial.bits` | Integer | `8` | `pwn-mesh` (serial) | Serial data bits. |
| `plugins.meshtastic.serial.stop` | Integer | `1` | `pwn-mesh` (serial) | Serial stop bits. |
| `plugins.meshtastic.serial.parity` | Symbol | `:none` | `pwn-mesh` (serial) | Serial parity. |
| `plugins.meshtastic.mqtt.host` | String | `mqtt.meshtastic.org` | `pwn-mesh` → `Meshtastic::MQTT.connect` | MQTT broker hostname. |
| `plugins.meshtastic.mqtt.port` | Integer | `1883` | `pwn-mesh` | MQTT broker port. |
| `plugins.meshtastic.mqtt.tls` | Boolean | `false` | `pwn-mesh` | Use TLS to the MQTT broker. |
| `plugins.meshtastic.mqtt.user` | String | `meshdev` | `pwn-mesh` | MQTT username. |
| `plugins.meshtastic.mqtt.pass` | String | `large4cats` | `pwn-mesh` | MQTT password. |
| `plugins.meshtastic.channel.active` | String | `LongFast` | `pwn-mesh` | Which named channel block below is used for TX/RX. |
| `plugins.meshtastic.channel.<NAME>.psk` | String (b64) | `AQ==` | `pwn-mesh` | Channel pre-shared key. |
| `plugins.meshtastic.channel.<NAME>.region` | String | — | `pwn-mesh` | LoRa region tag (e.g. `US/UT`). |
| `plugins.meshtastic.channel.<NAME>.topic` | String | — | `pwn-mesh` | MQTT topic filter to subscribe/publish (e.g. `2/e/#`). |
| `plugins.meshtastic.channel.<NAME>.channel_num` | Integer | — | `pwn-mesh` | Meshtastic channel index. |
| `plugins.meshtastic.channel.<NAME>.from` | String | `!<mqtt client_id>` | `pwn-mesh` | Sender node id used on outbound packets. |
| `plugins.shodan.api_key` | String | — | `PWN::Plugins::Shodan` | Shodan API key (passed as `api_key:` to `Shodan.*`). |

### `memory` / `sessions` / `cron`

| Key path | Type | Default | Consumed by | Purpose |
|---|---|---|---|---|
| `memory.enabled` | Boolean | `true` | `PWN::Memory` | Reserve — persistent memory on/off (currently always active; future gate). |
| `memory.provider` | String | `file` | `PWN::Memory` | Storage backend: `file` (`~/.pwn/memory.json`). `sqlite` reserved. |
| `sessions.enabled` | Boolean | `true` | `PWN::Sessions` | Reserve — transcript recording on/off (currently always active; future gate). |
| `sessions.provider` | String | `jsonl` | `PWN::Sessions` | Transcript format under `~/.pwn/sessions/`. |
| `cron.enabled` | Boolean | `true` | `PWN::Cron` | Reserve — scheduled-job subsystem on/off (currently always active; future gate). |
| `cron.provider` | String | `yaml` | `PWN::Cron` | Job store format (`~/.pwn/cron/jobs.yml`). |

### Top-level / miscellaneous

| Key path | Type | Default | Consumed by | Purpose |
|---|---|---|---|---|
| `targets` | Array\<String\> | — | `PWN::AI::Agent::Extrospection.web_anchors` | Engagement-scope URLs/hosts. Merged into `:web` snapshot anchors when `ai.agent.extrospection.web.allow_targets: true`. |

---

## Runtime-only keys on `PWN::Env` (NOT stored in `pwn.yaml`)

These are injected by `PWN::Config.refresh_env` / `PWN::AI::Agent::Loop` after
the YAML is decrypted. They will appear on `PWN::Env` in-process but are
**overwritten on every load**, so putting them in `pwn.yaml` has no effect.

| Key path | Set by | Purpose |
|---|---|---|
| `driver_opts.pwn_env_path` | `PWN::Config.refresh_env` / `PWN::Driver::Parser` | Resolved path to the active `pwn.yaml` (from `--pwn_env` or default). |
| `driver_opts.pwn_dec_path` | `PWN::Config.refresh_env` / `PWN::Driver::Parser` | Resolved path to the decryptor YAML (from `--pwn_dec` or default). |
| `pwn_skills_path` | `PWN::Config.refresh_env` | Absolute path to `~/.pwn/skills/`. |
| `pwn_memory_path` | `PWN::Config.refresh_env` | Absolute path to `~/.pwn/memory.json`. |
| `pwn_sessions_path` | `PWN::Config.refresh_env` | Absolute path to `~/.pwn/sessions/`. |
| `pwn_cron_path` | `PWN::Config.refresh_env` | Absolute path to `~/.pwn/cron/`. |
| `ai.<engine>.response_history` | `PWN::Config.refresh_env` | Rolling chat history for the active engine (reset on every reload). |
| `ai.session_id` | `PWN::AI::Agent::Loop.run` | Active `PWN::Sessions` id for the current turn (read by `sessions_current`, `mistakes_record`). |

---

## Redaction

`PWN::Config.redact_sensitive_artifacts` (and therefore `PWN::EnvRedacted`)
masks any key named: `admin_key`, `api_key`, `auth_client_secret`,
`bearer_token`, `client_secret`, `consumer_key`, `key`, `pass`, `password`,
`psk`, `refresh_token`, `secret_key`, `token`. Use those key names for any
custom secrets you add so they never leak into logs, transcripts, or the
agent system prompt.

---

## Related files under `~/.pwn/`

`pwn.yaml` is the only file you edit; everything else is machine-written
state. See **[Persistence](Persistence.md)** for the full map
(`memory.json`, `memory.idx`, `learning.jsonl`, `mistakes.json`,
`metrics.json`, `extrospection.json`, `sessions/`, `skills/`,
`finetune/`, `cron/`, `agents.yml`, `swarm/`).

Multi-agent personas are **not** configured here — they live in
`~/.pwn/agents.yml` and are managed with `agent_spawn` / `agent_list`
(see **[Swarm](Swarm.md)**).

[← Home](Home.md) · [Persistence](Persistence.md) · [pwn-ai Agent](pwn-ai-Agent.md) · [Extrospection](Extrospection.md)
