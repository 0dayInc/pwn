# Configuration - `~/.pwn/pwn.yaml`

Everything configurable in PWN lives in **one encrypted YAML file**, loaded by
`PWN::Config.refresh_env` at driver startup and exposed in-process as the
frozen constant **`PWN::Env`** (a redacted copy is available as
`PWN::EnvRedacted`).

The file is **AES-encrypted at rest** by `PWN::Plugins::Vault`. Its key/IV
live in a sibling **`~/.pwn/pwn.yaml.decryptor`** file (or in
`PWN_DECRYPTOR_KEY` / `PWN_DECRYPTOR_IV` env vars). Never edit `pwn.yaml`
by hand - use the **`pwn-vault`** REPL command, which decrypts, opens
`$EDITOR`, re-encrypts, and reloads `PWN::Env`. If `PWN::Config` rejects the
edited file, the editor reopens until the vault loads cleanly, so you do not
leave the REPL stuck on a decrypt / re-edit / encrypt loop.

If `~/.pwn/pwn.yaml` does not exist on first run, `PWN::Config.default_env`
writes a fully-commented template with every key below (values set to
`'optional - ...'` / `'required - ...'` placeholder strings), encrypts it, and
generates the decryptor.

> **Before configuring**, run `pwn setup` - the
> [doctor](Installation.md#pwn-setup--the-post-install-doctor--provisioner)
> reports whether `~/.pwn/`, `pwn.yaml`, its decryptor, and an AI-engine key
> are present, and exits non-zero for CI if any are missing.
> After `gem update pwn`, run `pwn setup --migrate --fix` - `PWN::Migrate`
> deep-merges any keys the new `PWN::Config.env_template` added into your
> encrypted `pwn.yaml` **without overwriting your values**.

---

## Full annotated example

```yaml
# ~/.pwn/pwn.yaml  (shown DECRYPTED - file is AES-encrypted on disk)

ai:
  active: grok                     # Which engine backs `pwn-ai`. One of: openai | anthropic | grok | gemini | ollama | openwebui.
  module_reflection: false         # Master gate for LLM self-analysis (SAST triage, Burp enrichment, Learning.llm_reflect).

  grok:
    base_uri: https://api.x.ai/v1  # xAI API base URL. Override for a self-hosted proxy / private endpoint.
    key: xai-...                     # xAI API key. If blank AND no oauth.* below, PWN prompts interactively at load.
    model: <model-id>              # Model id sent on every chat / tool-loop request. See provider docs / API for currently-supported ids.
    system_role_content: 'You are an ethically hacking xAI Grok agent.'   # Base system prompt (MEMORY/SKILLS/LEARNING/EXTROSPECTION blocks are appended to this).
    temp: 1.0                      # Sampling temperature passed to the chat endpoint.
    max_prompt_length: 256000      # Soft input-context ceiling (chars) used for prompt truncation / chunking.
    oauth:                         # RFC-8628 device-flow (SuperGrok subscription) - public client, no client_secret.
      refresh_token: ~             # Durable OAuth refresh token; enables silent re-auth without an API key.
      bearer_token: ~              # Short-lived OAuth access JWT; auto-refreshed each run when refresh_token is set.
      client_id: b1a00492-073a-47ea-816f-4c329264a828   # xAI's PUBLIC OAuth client id for the "Grok CLI" application (not sensitive).
      client_secret: ~             # Only for confidential-client OAuth flows; unused by the public Grok-CLI client.
      scope: 'openid profile email offline_access grok-cli:access api:access'   # OAuth scope string requested during device-flow enrollment.
      token_uri: https://auth.x.ai/oauth2/token          # OAuth token endpoint (override for enterprise IdP).
      enroll: false                # true → force RFC-8628 device-flow enrollment on load even when `key:` is set.

  openai:
    base_uri: https://api.openai.com/v1   # OpenAI API base URL. Override for Azure OpenAI / VPC gateway / local proxy.
    key: sk-...                             # OpenAI API key (`sk-...`). Prompted interactively if blank.
    model: <model-id>                     # Model id sent on every chat / tool-loop request. See provider docs / API for currently-supported ids.
    system_role_content: 'You are an ethically hacking OpenAI agent.'   # Base system prompt for this engine.
    temp: 1.0                             # Sampling temperature.
    max_prompt_length: 128000             # Soft input-context ceiling (chars) for truncation / chunking.
    max_tokens: 16384                     # Max OUTPUT tokens per response. Mapped to OpenAI wire param `max_completion_tokens`.

  anthropic:
    base_uri: https://api.anthropic.com/v1   # Anthropic API base URL. Override for Bedrock / private gateway.
    key: sk-ant-...                            # Anthropic API key (`sk-ant-...`). Prompted interactively if blank.
    model: <model-id>                        # Model id sent on every chat / tool-loop request. See provider docs / API for currently-supported ids.
    system_role_content: 'You are an ethically hacking Anthropic agent.'   # Base system prompt for this engine.
    temp: 1.0                                # Sampling temperature.
    max_tokens: 8192                         # Max OUTPUT tokens per response. Raise if tool-call JSON truncates.
    max_prompt_length: 200000                # Soft input-context ceiling (chars) for truncation / chunking.

  gemini:
    base_uri: https://generativelanguage.googleapis.com/v1beta   # Google Generative Language API base URL.
    key: AIza...                               # Google AI Studio API key (`AIza...`). Prompted interactively if blank.
    model: <model-id>                        # Model id sent on every chat / tool-loop request. See provider docs / API for currently-supported ids.
    system_role_content: 'You are an ethically hacking Gemini agent.'   # Base system prompt for this engine.
    temp: 1.0                                # Sampling temperature.
    max_prompt_length: 1000000               # Soft input-context ceiling (chars) - Gemini supports very large contexts.

  ollama:
    base_uri: http://127.0.0.1:11434         # Direct Ollama server. Optional; this is the stock default. No vendor key.
    key: ~                                   # Only if a reverse-proxy sits in front of Ollama. Stock ollama needs none.
    model: <local-model-tag>                 # Local model tag exactly as `ollama list` shows it.
    embed_model: nomic-embed-text            # Embedding model for PWN::MemoryIndex (relevance-ranked MEMORY). Must be pulled locally.
    system_role_content: 'You are an ethically hacking Ollama agent.'   # Base system prompt for this engine.
    temp: 1.0                                # Sampling temperature (used on the FINAL text-only turn - tool-bearing turns are pinned low for deterministic routing).
    tool_temp: 0.1                           # Lower temperature on tool-bearing turns for stable routing.
    num_ctx: 32768                           # Context window passed to /api/chat options.num_ctx. Ollama's default (2048) is too small for the pwn-ai system prompt.
    num_predict: 4096                        # Decode-length cap so a thinking model cannot stream forever.
    keep_alive: 30m                          # How long ollama keeps the model resident between iterations (avoids reload latency mid-turn).
    result_max: 4000                         # Tool-result cap for local models (frontier keeps Result::DEFAULT_MAX).
    prompt_budget:                           # Per-block caps applied by PromptBuilder.budget so a small model spends attention on the request, not the harness.
      memory: 6                              # Max MEMORY entries injected (relevance-ranked via PWN::MemoryIndex when available).
      metrics: 3                             # Max TOOL EFFECTIVENESS rows.
      mistakes: 3                            # Max KNOWN MISTAKES / FIXES rows.
      learning: 2                            # Max recent LEARNING outcomes shown.
      extro: false                           # Gate the (heaviest) EXTROSPECTION block entirely for local models.
    max_prompt_length: 32000                 # Soft input-context ceiling (chars) - tune per local model's real context window.

  openwebui:
    base_uri: https://openwebui.local        # REQUIRED - Open WebUI gateway (separate provider from ollama).
    key: eyJ...                                # REQUIRED - Open WebUI JWT (Settings -> Account -> API Key).
    model: <model-id-or-tag>                 # Model id / tag Open WebUI exposes.
    embed_model: nomic-embed-text            # Used when a direct ollama embed_model is unset.
    system_role_content: 'You are an ethically hacking Open WebUI agent.'
    temp: 1.0
    tool_temp: 0.1
    num_ctx: 32768
    num_predict: 4096
    keep_alive: 30m
    result_max: 4000
    prompt_budget: { memory: 6, metrics: 3, mistakes: 3, learning: 2, extro: false }
    max_prompt_length: 32000

  reflect_engine: ~                # Teacher-student reflection: EXECUTE on ai.active, but write durable lessons via THIS engine (nil = same as active). Lets a local model act while a frontier model authors the Memory :lesson entries it reads back.

  agent:
    native_tools: true             # Use provider-native tool_calls / function-calling. false → legacy text-parsed tool protocol.
    max_iters: 777                 # Hard cap on tool-call rounds per user turn. Scars do not lower it.
    task_summary: true             # Executive task briefs via TaskSummarizer (plan + about_to). false disables.
    task_summary_every: 5          # When task_summary_verbose: emit Progress every N completed tools.
    task_summary_interval_s: 8.0   # When verbose: also emit when this many seconds elapsed.
    task_summary_verbose: false    # Mid-flight Progress/Finished lines (default: only plan + about_to).
    task_summary_llm: true         # LLM tangible-task decompose (default on). false = offline fallback.
    max_depth: 3                   # Recursion guard: how many levels deep agent_ask/agent_debate sub-agents may spawn sub-agents.
    auto_introspect: true          # Run Learning.auto_introspect (outcome logging + lesson mining) after every final answer.
    auto_extrospect: true          # Ambient baseline after every final answer (host/repo/env ONLY - never launches burpsuite/zaproxy/msf/gqrx). Sense tools stay on-demand.
    defer_introspect: true         # Run auto_introspect on a background thread AFTER the user-visible reply (default on). Specs/cron stay inline.
    prompt_cache: true             # Engine-native prefix cache. Anthropic cache_control, OpenAI prompt_cache_key, Grok x-grok-conv-id, Gemini systemInstruction split. Ollama / Open WebUI have none.
    recon_authorized: false        # Allow live subnet sweeps / raw-socket discovery tools this session
    shell_bash: false              # true -> run shell via bash -lc. Default is /bin/sh.
    plan_first: ~                  # Plan-then-act pre-pass. nil = auto (true when ai.active is ollama or openwebui).
    tool_router: ~                 # Dynamic tool-set slimming. nil = auto (true for ollama / openwebui).
    tool_preference:               # Same order as CORE_TOOLS: memory_recall, session_recall, skills_recall, pwn_eval, shell, mistakes_record, mistakes_resolve, learning_note_outcome, memory_remember. Current session is injected separately.
      - memory_recall
      - session_recall
      - skills_recall
      - pwn_eval
      - shell
      - mistakes_record
      - mistakes_resolve
      - learning_note_outcome
      - memory_remember
    escalation_persona: escalator  # Swarm persona for a 3-line corrective hint after enough in-turn failures. nil = disabled.
    local_introspect: failure_only # End-of-turn auto_introspect policy for local engines: always | failure_only | every_n.
    policy: true                   # Live tabular Q / REINFORCE. Advisory only; never replaces TaskSummarizer / plan_first. false disables.
    toolsets: ~                    # Allow-list of toolsets exposed to the agent. nil = all. Valid: cron, curriculum, extrospection, learning, memory, metrics, policy, pwn, reward, sessions, skills, swarm, terminal.
    extrospection:
      web:
        anchors:                   # URLs the headless browser fingerprints on extro_snapshot(sections:[:web]). Alias: web_anchors.
          - https://nvd.nist.gov
          - https://www.exploit-db.com
        proxy: ~                   # Upstream proxy for TransparentBrowser during probe_web/verify/watch (e.g. 'tor', http://127.0.0.1:8080).
        max_anchors: 8             # Cap on how many anchors are rendered per snapshot (protects run time).
        per_page_timeout: 15       # Seconds before a single page render is abandoned and recorded as unreachable.
        screenshot: false          # Persist a PNG per anchor to ~/.pwn/extrospection/web/ (disk-heavy; off by default).
        allow_targets: false       # true → also merge top-level `targets:` into anchors (opt-in - off so in-scope hosts aren't touched unprompted).
      rf:
        host: 127.0.0.1            # GQRX remote-control host for extro_rf_tune.
        port: 7356                 # GQRX remote-control port.
        settle_secs: 8             # Seconds to sample RDS after tuning (max 30).
        ttl: 300                   # Observation TTL for :rf (songs change - keep short).
      osint:
        ttl: 86400                 # Observation TTL for :osint (default 1 day).
        proxy: ~                   # Optional upstream proxy for OSINT HTTP feeds.
        api_keys:                  # Per-feed API keys (all optional; keyed feeds return {skipped:} when absent). ENV fallbacks also honored.
          shodan: ...              #   ← SHODAN_API_KEY
          hunter: ...              #   ← HUNTER_API_KEY
          abuseipdb: ...           #   ← ABUSEIPDB_API_KEY
          virustotal: ...          #   ← VIRUSTOTAL_API_KEY / VT_API_KEY
          greynoise: ...           #   ← GREYNOISE_API_KEY
          haveibeenpwned: ...      #   ← HIBP_API_KEY
          securitytrails: ...      #   ← SECURITYTRAILS_API_KEY
          steam: ...               #   ← STEAM_API_KEY
        social:
          sites_file: etc/osint/social_sites.json   # Vendored sherlock-derived presence list used by :social_sweep. Override to extend.
          max_threads: 16          # Concurrent presence checks in :social_sweep.
          max_sites: 120           # Hard cap on sites read from sites_file.
          timeout: 6               # Per-site HTTP timeout (seconds).
          mastodon_instance: mastodon.social         # Default Fediverse instance for a bare @handle.
        bridges:
          timeout: 120             # Per local-tool wall clock (seconds) for theHarvester/amass/spiderfoot/recon-ng.
          theharvester_sources: anubis,crtsh,hackertarget,otx,rapiddns,urlscan,certspotter,dnsdumpster,duckduckgo
          spiderfoot_modules: sfp_dnsresolve,sfp_crt,sfp_hackertarget,sfp_dnsdumpster,sfp_wayback,sfp_social
          amass_passive: true      # false → active enum (touches target DNS - OPSEC).

plugins:
  asm:
    arch: x86_64                   # Target architecture for `pwn-asm` inline assembler/disassembler. Default: PWN::Plugins::DetectOS.arch.
    endian: little                 # Endianness for `pwn-asm` (little | big). Default: PWN::Plugins::DetectOS.endian.
  blockchain:
    bitcoin:
      rpc_host: localhost          # bitcoind JSON-RPC host for PWN::Blockchain::BTC.
      rpc_port: 8332               # bitcoind JSON-RPC port.
      rpc_user: ...                  # bitcoind RPC username (rpcauth / rpcuser in bitcoin.conf).
      rpc_pass: ...                  # bitcoind RPC password. Redacted in PWN::EnvRedacted.
  hunter:
    api_key: ...                     # hunter.how API key - passed as api_key: to PWN::Plugins::Hunter.search.
  jira_data_center:
    base_uri: https://jira.company.com/rest/api/latest   # Jira Data Center REST base URL.
    token: ...                       # Jira Personal Access Token for PWN::Plugins::JiraDataCenter. Redacted.
  meshtastic:
    admin_key: ...                   # Public key authorised to send admin messages to mesh nodes via `pwn-mesh`.
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
      LongFast:                    # Channel definition - name is arbitrary, referenced by `active:` above.
        psk: 'AQ=='                # Channel pre-shared key (base64). 'AQ==' = Meshtastic default public key. Redacted.
        region: US/UT              # LoRa region tag (regulatory band).
        topic: 2/e/#               # MQTT topic filter to subscribe/publish for this channel.
        channel_num: 8             # Meshtastic channel index (slot number on the device).
        from: '!deadbeef'          # Sender node id used on outbound packets. Optional - defaults to !<mqtt client_id>.
      PWN:                         # Example second (private) channel definition.
        psk: ...                     # Private channel pre-shared key (base64). Redacted.
        region: US/UT              # LoRa region tag for this channel.
        topic: 2/e/PWN/#           # MQTT topic filter for this channel.
        channel_num: 99            # Meshtastic channel index for this channel.
  shodan:
    api_key: ...                     # Shodan API key - passed as api_key: to PWN::Plugins::Shodan.*. Redacted.

memory:
  enabled: true                    # Reserve - persistent-memory subsystem on/off (currently always active; future gate).
  provider: file                   # Storage backend for PWN::Memory: file (~/.pwn/memory.json). `sqlite` reserved.

sessions:
  enabled: true                    # Reserve - transcript recording on/off (currently always active; future gate).
  provider: jsonl                  # Transcript format under ~/.pwn/sessions/ (one .jsonl per session).

cron:
  enabled: true                    # Reserve - scheduled-job subsystem on/off (currently always active; future gate).
  provider: yaml                   # Job store format for PWN::Cron (~/.pwn/cron/jobs.yml).

targets:                           # Optional - engagement-scope URLs/hosts. Merged into :web snapshot anchors
  - https://target.example.com     #   ONLY when ai.agent.extrospection.web.allow_targets: true.
```

---

## Reading / writing at runtime

```ruby
PWN::Env[:ai][:active]                          # => :grok
PWN::Env.dig(:ai, :agent, :max_iters)           # => 777
PWN::EnvRedacted[:ai][:grok][:key]              # => ">>> REDACTED >>> ..."

# Edit + re-encrypt + reload without leaving the REPL:
pwn-vault

# Force a reload from disk (e.g. after pwn-vault in another shell):
PWN::Config.refresh_env
```

---

## Full key reference

### `ai` - AI engines & agent loop

| Key path | Type | Default | Consumed by | Purpose |
|---|---|---|---|---|
| `ai.active` | String | `grok` | `PWN::Config.refresh_env`, `PWN::AI::Agent::Loop`, `PWN::Plugins::REPL`, `PWN::Cron` | Which AI engine backs `pwn-ai`. One of `openai` · `anthropic` · `grok` · `gemini` · `ollama` · `openwebui`. |
| `ai.module_reflection` | Boolean | `false` | `PWN::AI::Agent::Reflect`, `PWN::SAST::*`, `PWN::Plugins::BurpSuite` | Master gate for LLM-driven self-analysis (SAST triage, Burp finding enrichment, `Learning.llm_reflect`). |
| `ai.<engine>.base_uri` | String | provider default | `PWN::AI::<Engine>.rest_call` | Override the API base URL (self-hosted proxy, private endpoint, Azure/VPC gateway). Optional for stock `ollama` (`http://127.0.0.1:11434`). **Required** for `openwebui`. |
| `ai.<engine>.key` | String | - | `PWN::AI::<Engine>` | API key / bearer token. Stock `ollama` needs none. `openwebui` requires a JWT. If blank AND no OAuth is configured on a key-backed engine, PWN prompts interactively at load. |
| `ai.<engine>.model` | String | provider default | `PWN::AI::<Engine>.chat` / `.chat_tool_loop` | Model id sent on every request. Use whatever id the provider / `ollama list` currently exposes - PWN never hard-codes a specific model. |
| `ai.<engine>.system_role_content` | String | ethical-hacker persona | `PWN::AI::Agent::PromptBuilder`, `PWN::Plugins::REPL` | Base system prompt prepended to MEMORY / SKILLS / LEARNING / EXTROSPECTION blocks. |
| `ai.<engine>.temp` | Float | `1.0` | `PWN::AI::<Engine>.chat` | Sampling temperature. |
| `ai.<engine>.max_prompt_length` | Integer | per-engine | `PWN::AI::<Engine>`, `PWN::Plugins::REPL` | Soft input-context ceiling used for prompt truncation / chunking. |
| `ai.anthropic.max_tokens` | Integer | `8192` | `PWN::AI::Anthropic.chat_tool_loop` | Max **output** tokens per response. Raise if tool-call JSON truncates. |
| `ai.openai.max_tokens` | Integer | `16384` | `PWN::AI::OpenAI.chat` | Max **output** tokens per response. Mapped to OpenAI's wire param `max_completion_tokens` (legacy env key `max_completion_tokens` still accepted). |
| `ai.ollama.embed_model` | String | provider default | `PWN::MemoryIndex` | Local embedding model tag used to build `~/.pwn/memory.idx` for **relevance-ranked** MEMORY injection. Falls back to substring recall when unset / unreachable. |
| `ai.ollama.num_ctx` | Integer | `32768` | `PWN::AI::Ollama.chat_with_tools` | Context window sent as `options.num_ctx` on the native `/api/chat` call. Ollama's own default (2048) truncates the pwn-ai system prompt. |
| `ai.ollama.keep_alive` | String | `30m` | `PWN::AI::Ollama.chat_with_tools` | How long the model stays resident in ollama between iterations of a single turn. |
| `ai.ollama.num_predict` | Integer | `4096` | `PWN::AI::Ollama.chat_with_tools` | Decode-length cap so a thinking model cannot stream forever. |
| `ai.ollama.tool_temp` | Float | `0.1` | `PWN::AI::Ollama.chat_with_tools` | Sampling temperature on tool-bearing turns (final text-only turn uses `temp`). |
| `ai.ollama.result_max` | Integer | `4000` | `PWN::AI::Agent::Result` | Tool-result cap for local models. |
| `ai.openwebui.*` | (same shape as `ollama`) | JWT + `base_uri` required | `PWN::AI::OpenWebUI` | Separate provider from `ollama`. OpenAI-compatible `/api/v1/chat/completions` plus proxied `/ollama/api/*` (including embed). |
| `ai.ollama.prompt_budget` | Hash | `{memory:6, metrics:3, mistakes:3, learning:2, extro:false}` | `PWN::AI::Agent::PromptBuilder.budget` | Per-block caps on injected context so a small local model spends its attention on the request, not the harness. Any engine may set this. |
| `ai.reflect_engine` | Symbol \| `nil` | `nil` (= `ai.active`) | `PWN::AI::Agent::Reflect.on`, `Learning.reflect` | **Teacher-student** override: run the task on `ai.active`, but generate durable lessons via *this* engine. Lets a local model execute while a frontier model writes the Memory it reads back. |
| `ai.grok.oauth.refresh_token` | String | - | `PWN::AI::Grok.resolve_auth` | Durable OAuth refresh token (from `PWN::AI::Grok.obtain_oauth_bearer_token` device flow). Enables silent re-auth without an API key. |
| `ai.grok.oauth.bearer_token` | String | - | `PWN::AI::Grok.resolve_auth` | Short-lived OAuth access JWT. Auto-refreshed each run when `refresh_token` is present; live-cached back into this hash. |
| `ai.grok.oauth.client_id` | String | Grok-CLI public id | `PWN::AI::Grok` | Override the public OAuth client id used for device-flow / refresh. |
| `ai.grok.oauth.client_secret` | String | - | `PWN::Config.refresh_env`, `PWN::AI::Grok` | Only for confidential-client OAuth flows. Unused by the default public Grok-CLI client. |
| `ai.grok.oauth.scope` | String | see example | `PWN::AI::Grok` | OAuth scope string requested during device-flow enrollment. |
| `ai.grok.oauth.token_uri` | String | `https://auth.x.ai/oauth2/token` | `PWN::AI::Grok` | OAuth token endpoint (override for enterprise IdP). |
| `ai.grok.oauth.enroll` | Boolean | `false` | `PWN::AI::Grok` | `true` → always run RFC-8628 device-flow enrollment on load, even when `ai.grok.key` is set. |

### `ai.agent` - pwn-ai autonomous loop

| Key path | Type | Default | Consumed by | Purpose |
|---|---|---|---|---|
| `ai.agent.native_tools` | Boolean | `true` | `PWN::Plugins::REPL` (`pwn-ai` cmd) | Use provider-native `tool_calls` / function-calling. `false` falls back to the legacy text-parsed tool protocol. |
| `ai.agent.max_iters` | Integer | `777` | `PWN::AI::Agent::Loop.run`, `PWN::AI::Agent::Swarm` | Hard cap on tool-call rounds per user turn. Budget-hot scars and overconfidence do not lower this request's runway. |
| `ai.agent.task_summary` | Boolean | `true` | `PWN::AI::Agent::TaskSummarizer`, `Loop` | Master switch for executive task briefs (`emit_plan!` / `about_to`). |
| `ai.agent.task_summary_every` | Integer | `5` | `TaskSummarizer.every_n` | Verbose progress cadence (tools). |
| `ai.agent.task_summary_interval_s` | Float | `8.0` | `TaskSummarizer.interval_s` | Verbose progress cadence (seconds). |
| `ai.agent.task_summary_verbose` | Boolean | `false` | `TaskSummarizer.verbose?` | Emit mid-flight `Progress:` / `Finished:` lines; default keeps only plan + about_to. |
| `ai.agent.task_summary_llm` | Boolean \| `nil` | `nil` (on) | `TaskSummarizer.llm_plan_enabled?` | LLM tangible-task decomposition. `false` forces offline generic fallback (tests / air-gap). |
| `ai.agent.max_depth` | Integer | `3` | `PWN::AI::Agent::Swarm` | Recursion guard for `agent_ask` / `agent_debate` sub-agents spawning sub-agents. |
| `ai.agent.auto_introspect` | Boolean | `true` | `PWN::AI::Agent::Learning.auto_introspect` | Run outcome logging + lesson mining after every final answer. Toggle live via `learning_auto_introspect_toggle`. |
| `ai.agent.auto_extrospect` | Boolean | `true` | `PWN::AI::Agent::Extrospection.auto_extrospect` | Ambient baseline after every final answer (`AUTO_SECTIONS` = host/repo/env only; never spawns GUI/JVM tools). Sense tools (`intel`/`verify`/`watch`/`rf_tune`/`observe`) stay on-demand. Toggle live via `extro_auto_toggle`. |
| `ai.agent.toolsets` | Array\<String\> \| `nil` | `nil` (all) | `bin/pwn`, `PWN::Plugins::REPL`, `PWN::AI::Agent::Registry` | Allow-list of toolsets exposed to the agent. Valid: `cron`, `curriculum`, `extrospection`, `learning`, `memory`, `metrics`, `policy`, `pwn`, `reward`, `sessions`, `skills`, `swarm`, `terminal`. |
| `ai.agent.recon_authorized` | Boolean | `false` | `PWN::AI::Agent::ToolGuard.recon_authorized?` / `Loop.recon_authorized?` | When true (or the user request contains in-scope / engagement language), live host-discovery tools may run. Default refuses unauthorized sweeps. |
| `ai.agent.shell_bash` | Boolean | `false` | `PWN::AI::Agent::ToolGuard.shell_bash?` | When true, `shell` runs via `bash -lc` so bash-only syntax is allowed. Default is POSIX `/bin/sh` and bashisms are rejected with a rewrite hint. |
| `ai.agent.plan_first` | Boolean \| `nil` | `nil` (auto: `true` when `ai.active` is `ollama` or `openwebui`) | `PWN::AI::Agent::Loop.plan_first` | Plan-then-act pre-pass: the model must emit a numbered tool plan (as an assistant message) *before* it may dispatch anything. Cheap chain-of-thought scaffolding for local models. |
| `ai.agent.tool_router` | Boolean \| `nil` | `nil` (auto: `true` for `ollama` / `openwebui`) | `PWN::AI::Agent::Registry.definitions` | Dynamic tool-set slimming: expose only `Registry::CORE_TOOLS` + the top-K keyword-relevant schemas for *this* request. Ties break on historical `Metrics` success rate, then `ai.agent.tool_preference`. |
| `ai.agent.tool_preference` | Array\<String\> | `memory_recall`, `session_recall`, `skills_recall`, `pwn_eval`, `shell`, `mistakes_record`, `mistakes_resolve`, `learning_note_outcome`, `memory_remember` | `PWN::AI::Agent::Registry.preference_order` / `.rank` / `.apply_preference`, `Policy` | Same order as `CORE_TOOLS`. Current session is injected as RECENT TURNS. Explicit empty list disables preference. |
| `ai.agent.defer_introspect` | Boolean | `true` | `PWN::AI::Agent::TurnFinalizer` | Run `Learning.auto_introspect` on a background thread after the user-visible reply. Specs and cron stay inline. |
| `ai.agent.prompt_cache` | Boolean | `true` | `PWN::AI::Agent::PromptCache` | Engine-native prefix cache. Anthropic uses `cache_control`; OpenAI uses `prompt_cache_key`; Grok uses `x-grok-conv-id`; Gemini splits `systemInstruction`. Ollama and Open WebUI have no native prefix-cache field. |
| `ai.agent.local_introspect` | Symbol | `failure_only` | `PWN::AI::Agent::Learning.auto_introspect` | End-of-turn introspect policy for local engines: `always` · `failure_only` · `every_n` (with `introspect_every_n`). |
| `ai.agent.escalation_persona` | String \| `nil` | `escalator` | `PWN::AI::Agent::Loop.escalate` -> `Swarm.ask` | Circuit-breaker: once a local model accumulates enough in-turn failures, ask this Swarm persona for a 3-line corrective hint (injected as a synthetic tool result). The local model still authors the final answer so Learning/Metrics stay attributed. |
| `ai.agent.critic` | Boolean \| `nil` | `nil` (auto: on for remote, off for ollama) | `PWN::AI::Agent::Curriculum.critic` | Tool-armed constitutional self-critic reviews (and may `shell`/`extro_verify`) every final answer before it is returned. |
| `ai.agent.red_team_plan` | Boolean \| `nil` | `nil` (auto: on for remote, off for ollama) | `PWN::AI::Agent::Curriculum.red_team_plan` | Adversarial review of the `plan_first` numbered plan, grounded in Metrics/Mistakes/`extro_drift` telemetry, before the first dispatch. |
| `ai.agent.counterfactual` | Boolean \| `nil` | `nil` (auto: on for remote, off for ollama) | `PWN::AI::Agent::Curriculum.counterfactual` | On `[REPEATING]`, fork an alt-persona branch, judge both, and record the `(loser, winner)` DPO preference pair. |
| `ai.agent.hindsight` | Boolean | `true` | `PWN::AI::Agent::Curriculum.hindsight` | Hindsight Experience Replay - relabel a failed trajectory as `success:true` for whatever it *did* accomplish. Free positive samples from failures. |
| `ai.agent.policy` | Boolean | `true` | `PWN::AI::Agent::Policy` | Live tabular Q-learning + REINFORCE. Records `(s,a,r,s')` per tool step, trains on `Reward.judge` at episode end, and adds a small Q-advantage term to `Registry.rank`. Advisory only: never replaces TaskSummarizer or plan_first. |
| `ai.agent.reward_llm` | Boolean \| `nil` | `nil` (auto: on for remote, off for ollama) | `PWN::AI::Agent::Reward.judge` / `.prm` | Use a cheap LLM teacher for outcome/process judges even when `module_reflection` is false. Local ollama stays heuristic unless this is `true`. |
| `ai.agent.reward_model` | String \| `nil` | `nil` | `Reward.judge` / `.prm` | Optional cheaper model id for the ORM/PRM chat. Falls back to `ai.reflect_model`, then the active engine default. |
| `ai.agent.reward_llm_timeout` | Integer | `12` | `Reward.judge` / `.prm` | Seconds for the cheap ORM chat (clamped 2..30). Fail fast to the overlap heuristic rather than a 900s hang. |
| `ai.agent.verify_as_reward` | Boolean \| `nil` | `nil` (auto: ~10% local / always frontier when a claim matches) | `PWN::AI::Agent::Reward.verify_as_reward` | Ground the LLM judge score by browser-verifying any checkable claim in the final via `extro_verify`; verdict caps/floors `Reward.judge`. |
| `ai.agent.extrospection.web.anchors` | Array\<String\> | `DEFAULT_WEB_ANCHORS` | `PWN::AI::Agent::Extrospection.probe_web` | URLs the headless browser fingerprints on `extro_snapshot(sections:[:web])`. Alias: `web_anchors`. |
| `ai.agent.extrospection.web.proxy` | String | - | `Extrospection.probe_web` / `.verify` / `.watch` | Upstream proxy for `PWN::Plugins::TransparentBrowser` (e.g. `tor`, `http://127.0.0.1:8080`). |
| `ai.agent.extrospection.web.max_anchors` | Integer | `8` | `Extrospection.probe_web` | Cap on anchors rendered per snapshot. |
| `ai.agent.extrospection.web.per_page_timeout` | Integer | `15` | `Extrospection` (headless browser) | Seconds before a page render is abandoned. |
| `ai.agent.extrospection.web.screenshot` | Boolean | `false` | `Extrospection.probe_web` / `.watch` | Persist a PNG per anchor to `~/.pwn/extrospection/web/`. |
| `ai.agent.extrospection.web.allow_targets` | Boolean | `false` | `Extrospection.web_anchors` | Merge top-level `targets:` into the anchor list (opt-in - off by default to avoid touching in-scope hosts unprompted). |
| `ai.agent.extrospection.rf.host` | String | `127.0.0.1` | `Extrospection.rf_tune` | GQRX remote-control host for the RF sense organ. |
| `ai.agent.extrospection.rf.port` | Integer | `7356` | `Extrospection.rf_tune` | GQRX remote-control port. |
| `ai.agent.extrospection.rf.settle_secs` | Integer | `8` | `Extrospection.rf_tune` | Seconds to sample RDS after tuning (capped at 30). |
| `ai.agent.extrospection.rf.ttl` | Integer | `300` | `Extrospection.rf_tune` | TTL (seconds) for `:rf` observations written by `extro_rf_tune` (ephemeral radio content). |
| `ai.agent.extrospection.osint.ttl` | Integer | `86400` | `Extrospection.osint` | TTL (seconds) for `:osint` observations written by `extro_osint`. |
| `ai.agent.extrospection.osint.proxy` | String | - | `Extrospection.osint` | Optional upstream proxy for OSINT HTTP feeds. |
| `ai.agent.extrospection.osint.api_keys.<feed>` | String | - | `Extrospection.osint_api_keys` | Per-feed API keys for keyed OSINT sources: `shodan`, `hunter`, `abuseipdb`, `virustotal`, `greynoise`, `haveibeenpwned`, `securitytrails`, `steam`. Keyed feeds return `{skipped:}` when absent. ENV fallbacks (`SHODAN_API_KEY`, `HUNTER_API_KEY`, `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`/`VT_API_KEY`, `GREYNOISE_API_KEY`, `HIBP_API_KEY`, `SECURITYTRAILS_API_KEY`, `STEAM_API_KEY`) also honored. Redacted. |
| `ai.agent.extrospection.osint.social.sites_file` | Path | `etc/osint/social_sites.json` | `Extrospection.osint_social_sweep` | JSON of `{sites:{Name:{url:"...{u}...",absent_status:[404],absent_body:[...],head:bool}}}` used by the `:social_sweep` presence check. Vendored subset of sherlock-project (MIT). Override to add/remove platforms. |
| `ai.agent.extrospection.osint.social.max_threads` | Integer | `16` | `Extrospection.osint_social_sweep` | Concurrency for the presence sweep (`Concurrent::FixedThreadPool`). |
| `ai.agent.extrospection.osint.social.max_sites` | Integer | `120` | `Extrospection.osint_social_sweep` | Hard cap on sites loaded from `sites_file`. |
| `ai.agent.extrospection.osint.social.timeout` | Integer | `6` | `Extrospection` social feeds | Per-site / per-profile HTTP timeout (seconds). |
| `ai.agent.extrospection.osint.social.mastodon_instance` | String | `mastodon.social` | `Extrospection.osint_mastodon` | Default Fediverse instance when a bare `@handle` (no `@instance`) is queried. |
| `ai.agent.extrospection.osint.bridges.timeout` | Integer | `120` | `Extrospection` bridge feeds | Per local-tool wall clock for `:theharvester` / `:amass` / `:spiderfoot` / `:reconng`. |
| `ai.agent.extrospection.osint.bridges.theharvester_sources` | String | passive set | `Extrospection.osint_theharvester` | Comma-separated `-b` sources passed to theHarvester. |
| `ai.agent.extrospection.osint.bridges.spiderfoot_modules` | String | passive set | `Extrospection.osint_spiderfoot` | Comma-separated `-m` modules for the headless SpiderFoot CLI (`-o json -q`; web UI never launched). |
| `ai.agent.extrospection.osint.bridges.amass_passive` | Boolean | `true` | `Extrospection.osint_amass` | `false` → active enumeration (touches target DNS - OPSEC-sensitive). |

### `plugins` - module credentials & wiring

| Key path | Type | Default | Consumed by | Purpose |
|---|---|---|---|---|
| `plugins.asm.arch` | String | `DetectOS.arch` | `PWN::Plugins::REPL` (`pwn-asm`) | Target architecture for the inline assembler / disassembler prompt (`x86_64`, `arm64`, ...). |
| `plugins.asm.endian` | String | `DetectOS.endian` | `PWN::Plugins::REPL` (`pwn-asm`) | Endianness for the inline assembler (`little` / `big`). |
| `plugins.blockchain.bitcoin.rpc_host` | String | `localhost` | `PWN::Blockchain::BTC` | bitcoind JSON-RPC host. |
| `plugins.blockchain.bitcoin.rpc_port` | Integer | `8332` | `PWN::Blockchain::BTC` | bitcoind JSON-RPC port. |
| `plugins.blockchain.bitcoin.rpc_user` | String | - | `PWN::Blockchain::BTC` | bitcoind RPC username. |
| `plugins.blockchain.bitcoin.rpc_pass` | String | - | `PWN::Blockchain::BTC` | bitcoind RPC password. |
| `plugins.hunter.api_key` | String | - | `PWN::Plugins::Hunter` | hunter.how API key (passed as `api_key:` to `Hunter.search`). |
| `plugins.jira_data_center.base_uri` | String | - | `PWN::Plugins::JiraDataCenter` | Jira DC REST base (e.g. `https://jira.company.com/rest/api/latest`). |
| `plugins.jira_data_center.token` | String | - | `PWN::Plugins::JiraDataCenter` | Jira Personal Access Token. |
| `plugins.meshtastic.admin_key` | String | - | `PWN::Plugins::REPL` (`pwn-mesh`) | Public key authorised to send admin messages to mesh nodes. |
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
| `plugins.meshtastic.channel.<NAME>.region` | String | - | `pwn-mesh` | LoRa region tag (e.g. `US/UT`). |
| `plugins.meshtastic.channel.<NAME>.topic` | String | - | `pwn-mesh` | MQTT topic filter to subscribe/publish (e.g. `2/e/#`). |
| `plugins.meshtastic.channel.<NAME>.channel_num` | Integer | - | `pwn-mesh` | Meshtastic channel index. |
| `plugins.meshtastic.channel.<NAME>.from` | String | `!<mqtt client_id>` | `pwn-mesh` | Sender node id used on outbound packets. |
| `plugins.shodan.api_key` | String | - | `PWN::Plugins::Shodan` | Shodan API key (passed as `api_key:` to `Shodan.*`). |

### `memory` / `sessions` / `cron`

| Key path | Type | Default | Consumed by | Purpose |
|---|---|---|---|---|
| `memory.enabled` | Boolean | `true` | `PWN::Memory` | Reserve - persistent memory on/off (currently always active; future gate). |
| `memory.provider` | String | `file` | `PWN::Memory` | Storage backend: `file` (`~/.pwn/memory.json`). `sqlite` reserved. |
| `sessions.enabled` | Boolean | `true` | `PWN::Sessions` | Reserve - transcript recording on/off (currently always active; future gate). |
| `sessions.provider` | String | `jsonl` | `PWN::Sessions` | Transcript format under `~/.pwn/sessions/`. |
| `cron.enabled` | Boolean | `true` | `PWN::Cron` | Reserve - scheduled-job subsystem on/off (currently always active; future gate). |
| `cron.provider` | String | `yaml` | `PWN::Cron` | Job store format (`~/.pwn/cron/jobs.yml`). |

### Top-level / miscellaneous

| Key path | Type | Default | Consumed by | Purpose |
|---|---|---|---|---|
| `targets` | Array\<String\> | - | `PWN::AI::Agent::Extrospection.web_anchors` | Engagement-scope URLs/hosts. Merged into `:web` snapshot anchors when `ai.agent.extrospection.web.allow_targets: true`. |

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
(`.schema`, `memory.json`, `memory.idx`, `learning.jsonl`,
`preferences.jsonl`, `mistakes.json`, `metrics.json`,
`reward_sentinel.json`, `extrospection.json`, `sessions/`,
`skills/<name>/SKILL.md`, `curriculum/`, `finetune/`, `cron/`,
`agents.yml`, `swarm/`, `backup/`, `quarantine/`).

`pwn setup --migrate` verifies (and `--fix` autorepairs) every
one of them against the running gem version.

Multi-agent personas are **not** configured here - they live in
`~/.pwn/agents.yml` and are managed with `agent_spawn` / `agent_list`
(see **[Swarm](Swarm.md)**).

[← Home](Home.md) · [Persistence](Persistence.md) · [pwn-ai Agent](pwn-ai-Agent.md) · [Extrospection](Extrospection.md)
