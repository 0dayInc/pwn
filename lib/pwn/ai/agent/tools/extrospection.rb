# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/ai/agent/extrospection'

# Expose the OUTWARD-facing half of the pwn-ai learning feedback loop to
# the model. Where the `learning_*` / `metrics_*` tools are INTROSPECTIVE
# (self-telemetry, own outcomes, own transcripts), the `extro_*` tools are
# EXTROSPECTIVE: they probe, record and reason about the WORLD the agent
# operates in — host state, toolchain versions, network posture, repo
# drift, recon findings, and external threat-intel — and correlate that
# world-state back against introspective failures. Together they close
# BOTH halves of the feedback loop.

PWN::AI::Agent::Registry.register(
  name: 'extro_snapshot',
  toolset: 'extrospection',
  schema: {
    name: 'extro_snapshot',
    description: 'Capture a fingerprint of the OUTSIDE world (host, kernel, ' \
                 'distro, network interfaces, listening ports, toolchain ' \
                 'binary versions, pwn repo HEAD, ruby/engine env) and ' \
                 'persist it to ~/.pwn/extrospection.json. Returns ' \
                 '{snapshot:, drift:} where drift is the delta vs the ' \
                 'PREVIOUS snapshot. Run at the start of an engagement and ' \
                 'after any host change so extro_drift / extro_correlate ' \
                 'have a baseline.',
    parameters: {
      type: 'object',
      properties: {
        persist: { type: 'boolean', default: true, description: 'Write to disk & rotate previous baseline.' },
        sections: { type: 'array', items: { type: 'string', enum: %w[host net toolchain repo env rf web] }, description: 'Subset of probes (default all except web). auto_extrospect uses host/repo/env only; toolchain never launches GUI bins.' }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::AI::Agent::Extrospection) },
  handler: lambda { |args|
    o = {}
    o[:persist]  = args[:persist]  if args.key?(:persist)
    o[:sections] = args[:sections] if args.key?(:sections)
    PWN::AI::Agent::Extrospection.snapshot(o)
  }
)

PWN::AI::Agent::Registry.register(
  name: 'extro_drift',
  toolset: 'extrospection',
  schema: {
    name: 'extro_drift',
    description: 'Diff the current host/toolchain/network/repo state ' \
                 'against the last persisted snapshot. Returns ' \
                 '{changed:[], added:[], removed:[]} with dotted-path keys ' \
                 '(e.g. "toolchain.nmap", "net.listening", "repo.head"). ' \
                 'Use to detect when the environment moved under you ' \
                 'between sessions before trusting introspective metrics.',
    parameters: {
      type: 'object',
      properties: {
        live: { type: 'boolean', default: true, description: 'true = probe NOW vs stored snapshot; false = stored snapshot vs stored previous.' }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::AI::Agent::Extrospection) },
  handler: lambda { |args|
    o = {}
    o[:live] = args[:live] if args.key?(:live)
    PWN::AI::Agent::Extrospection.drift(o)
  }
)

PWN::AI::Agent::Registry.register(
  name: 'extro_observe',
  toolset: 'extrospection',
  schema: {
    name: 'extro_observe',
    description: 'Record a fact about the OUTSIDE world (recon finding, ' \
                 'service banner, target fingerprint, CVE match, network ' \
                 'topology note). This is the extrospective analogue of ' \
                 'learning_note_outcome — it persists WHAT YOU SAW rather ' \
                 'than HOW YOU PERFORMED. Observations are re-injected into ' \
                 'every future system prompt via the EXTROSPECTION block.',
    parameters: {
      type: 'object',
      properties: {
        source: { type: 'string', description: 'Where it came from (nmap, shodan, burp, cve, human, ...).' },
        data: { type: 'string', description: 'The observation itself.' },
        category: { type: 'string', enum: %w[recon vuln intel target network env rf web misc], default: 'misc' },
        target: { type: 'string', description: 'Host / IP / URL / asset the observation is about.' },
        tags: { type: 'array', items: { type: 'string' } },
        ttl: { type: 'integer', description: 'Seconds until stale (omit = forever).' }
      },
      required: %w[source data]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Extrospection) },
  handler: lambda { |args|
    PWN::AI::Agent::Extrospection.observe(
      source: args[:source],
      data: args[:data],
      category: args[:category],
      target: args[:target],
      tags: args[:tags],
      ttl: args[:ttl]
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'extro_observations',
  toolset: 'extrospection',
  schema: {
    name: 'extro_observations',
    description: 'Query recorded external observations from ' \
                 '~/.pwn/extrospection.json (the read-side of ' \
                 'extro_observe). Filter by source / category / target / ' \
                 'tag; newest-first. Use to recall recon findings and ' \
                 'threat-intel captured in prior sessions.',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'integer', default: 50 },
        source: { type: 'string' },
        category: { type: 'string' },
        target: { type: 'string' },
        tag: { type: 'string' },
        fresh_only: { type: 'boolean', default: false, description: 'Drop entries whose TTL has expired.' }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::AI::Agent::Extrospection) },
  handler: lambda { |args|
    PWN::AI::Agent::Extrospection.observations(
      limit: args[:limit] || 50,
      source: args[:source],
      category: args[:category],
      target: args[:target],
      tag: args[:tag],
      fresh_only: args[:fresh_only]
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'extro_intel',
  toolset: 'extrospection',
  schema: {
    name: 'extro_intel',
    description: 'Query external threat-intelligence feeds (NVD CVE API, ' \
                 'CIRCL CVE-Search, local searchsploit / Exploit-DB) for a ' \
                 'keyword, product, or CVE id. Best-effort: any feed that ' \
                 'is unreachable degrades to []. Set record:true to also ' \
                 'persist each hit as an :intel observation so ' \
                 'extro_correlate can match it against installed toolchain ' \
                 'versions on this host.',
    parameters: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Keyword / product+version / CVE-YYYY-NNNN.' },
        feeds: { type: 'array', items: { type: 'string', enum: %w[nvd circl exploitdb] } },
        limit: { type: 'integer', default: 5 },
        record: { type: 'boolean', default: false }
      },
      required: %w[query]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Extrospection) },
  handler: lambda { |args|
    PWN::AI::Agent::Extrospection.intel(
      query: args[:query],
      feeds: args[:feeds],
      limit: args[:limit],
      record: args[:record]
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'extro_correlate',
  toolset: 'extrospection',
  schema: {
    name: 'extro_correlate',
    description: 'THE join between introspection and extrospection. ' \
                 'Cross-references (a) Metrics tools with <50 % success ' \
                 'against toolchain drift / missing binaries, (b) Learning ' \
                 'failures against host/net/repo drift on the same day, ' \
                 '(c) recorded :intel observations against installed ' \
                 'component versions, (d) :web DOM drift on watched targets ' \
                 'against Learning failures citing that host, (e) refuted ' \
                 'extro_verify claims against stale PWN::Memory :fact ' \
                 'entries. Returns actionable findings so the ' \
                 'agent can distinguish "I did it wrong" from "the world ' \
                 'changed under me".',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'integer', default: 10 }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::AI::Agent::Extrospection) },
  handler: lambda { |args|
    PWN::AI::Agent::Extrospection.correlate(limit: args[:limit] || 10)
  }
)

PWN::AI::Agent::Registry.register(
  name: 'extro_stats',
  toolset: 'extrospection',
  schema: {
    name: 'extro_stats',
    description: 'Return world-awareness metrics: snapshot age & ' \
                 'fingerprint, observation count, drift counts ' \
                 '(changed/added/removed since previous), toolchain bins ' \
                 'present, listening-port count. The extrospective ' \
                 'counterpart to learning_stats.',
    parameters: { type: 'object', properties: {}, required: [] }
  },
  check: -> { defined?(PWN::AI::Agent::Extrospection) },
  handler: ->(_args) { PWN::AI::Agent::Extrospection.stats }
)

PWN::AI::Agent::Registry.register(
  name: 'extro_reset',
  toolset: 'extrospection',
  schema: {
    name: 'extro_reset',
    description: 'Wipe ~/.pwn/extrospection.json (snapshot, previous ' \
                 'baseline, and ALL recorded observations). Use when ' \
                 'moving to a new engagement / target scope so stale recon ' \
                 'and drift stop polluting the EXTROSPECTION prompt block. ' \
                 'IRREVERSIBLE — must pass confirm:true.',
    parameters: {
      type: 'object',
      properties: {
        confirm: { type: 'boolean', description: 'Must be true to actually reset.' }
      },
      required: %w[confirm]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Extrospection) },
  handler: lambda { |args|
    raise ArgumentError, 'refusing to reset extrospection without confirm:true' unless args[:confirm] == true

    before = PWN::AI::Agent::Extrospection.stats
    PWN::AI::Agent::Extrospection.reset
    { reset: true, cleared: before, file: PWN::AI::Agent::Extrospection::EXTRO_FILE }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'extro_auto_toggle',
  toolset: 'extrospection',
  schema: {
    name: 'extro_auto_toggle',
    description: 'Enable/disable OPTIONAL ambient baseline after every ' \
                 'final answer (PWN::Env[:ai][:agent][:auto_extrospect]). ' \
                 'When on, Learning.auto_introspect runs Extrospection.' \
                 'auto_extrospect with AUTO_SECTIONS (host/repo/env only) — ' \
                 'never toolchain/rf/web, never launches burpsuite/zaproxy/' \
                 'msfconsole/gqrx. Primary sensing stays on-demand (intel/' \
                 'verify/watch/observe). Omit `enabled` to only query.',
    parameters: {
      type: 'object',
      properties: {
        enabled: { type: 'boolean', description: 'Desired state. Omit to only query.' }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::Env) && PWN::Env.is_a?(Hash) },
  handler: lambda { |args|
    ai = PWN::Env[:ai]
    raise 'PWN::Env[:ai] is unavailable or immutable' unless ai.is_a?(Hash) && !ai.frozen?

    ai[:agent] = (ai[:agent] || {}).dup if ai[:agent].nil? || ai[:agent].frozen?
    prev = ai[:agent][:auto_extrospect] ? true : false
    ai[:agent][:auto_extrospect] = (args[:enabled] ? true : false) if args.key?(:enabled)
    { previous: prev, current: ai[:agent][:auto_extrospect] ? true : false }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'extro_verify',
  toolset: 'extrospection',
  schema: {
    name: 'extro_verify',
    description: 'Browser-backed SELF FACT-CHECK. Drives ' \
                 'PWN::Plugins::TransparentBrowser (:headless) against a ' \
                 'canonical source for the claim class (NVD/CVE.org for ' \
                 ':cve, rubygems/PyPI/GitHub for :version, the cited URL ' \
                 'for :doc, DuckDuckGo HTML for :generic), renders the DOM ' \
                 'with JS executed, and returns {claim:, kind:, verdict: ' \
                 ':confirmed|:refuted|:unknown, confidence:, evidence:[], ' \
                 'action_taken:}. On :refuted → Mistakes.record(tool:' \
                 "'assumption') so KNOWN MISTAKES warns every future run; " \
                 'on :confirmed → observe(:intel, ttl:30d); on :unknown → ' \
                 'Learning.note_outcome(tags:[needs_human]). This is the ' \
                 'PROACTIVE trigger that catches the model being wrong ' \
                 'about the world before a human does — the extrospective ' \
                 'mirror of mistakes_record.',
    parameters: {
      type: 'object',
      properties: {
        claim: { type: 'string', description: 'Factual claim to fact-check (a CVE assertion, "latest X is v1.2.3", a cited URL + quoted snippet, or free text).' },
        kind: { type: 'string', enum: %w[cve version doc generic], description: 'Force a verifier. Omit to auto-detect from the claim.' },
        url: { type: 'string', description: 'Explicit URL the claim cites (forces kind: :doc).' },
        commit: { type: 'boolean', default: true, description: 'Write Mistakes/observe/Learning on the verdict.' },
        proxy: { type: 'string', description: 'Upstream proxy for TransparentBrowser (e.g. "tor" or http://127.0.0.1:8080).' }
      },
      required: %w[claim]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Extrospection) && PWN::AI::Agent::Extrospection.respond_to?(:verify) },
  handler: lambda { |args|
    o = { claim: args[:claim] }
    o[:kind]   = args[:kind]   if args[:kind]
    o[:url]    = args[:url]    if args[:url]
    o[:commit] = args[:commit] if args.key?(:commit)
    o[:proxy]  = args[:proxy]  if args[:proxy]
    PWN::AI::Agent::Extrospection.verify(o)
  }
)

PWN::AI::Agent::Registry.register(
  name: 'extro_watch',
  toolset: 'extrospection',
  schema: {
    name: 'extro_watch',
    description: 'Passive change-detection on an external web artefact you ' \
                 'care about (a target /api/version, a vendor changelog, a ' \
                 'bug-bounty scope page). Renders the URL headlessly via ' \
                 'PWN::Plugins::TransparentBrowser, hashes the RENDERED DOM ' \
                 'text (JS-delivered changes count), captures title / TLS ' \
                 'cert fp / screenshot, and persists it as observe(' \
                 'category: :web). Re-running against the same URL returns ' \
                 '{changed: true|false, prior_sha:, current:{…}}; a ' \
                 'subsequent extro_snapshot(sections:["web"]) surfaces the ' \
                 'delta in drift() as ~web.<host>.dom_sha exactly like ' \
                 '~toolchain.nmap today.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'URL to render, hash and watch.' },
        selector: { type: 'string', description: 'CSS selector whose innerText to hash (default full body).' },
        ttl: { type: 'integer', description: 'Seconds until this :web observation is stale (default 604800 = 7d).' },
        tags: { type: 'array', items: { type: 'string' } },
        proxy: { type: 'string', description: 'Upstream proxy for TransparentBrowser (e.g. "tor").' }
      },
      required: %w[url]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Extrospection) && PWN::AI::Agent::Extrospection.respond_to?(:watch) },
  handler: lambda { |args|
    PWN::AI::Agent::Extrospection.watch(
      url: args[:url],
      selector: args[:selector],
      ttl: args[:ttl],
      tags: args[:tags],
      proxy: args[:proxy]
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'extro_rf_tune',
  toolset: 'extrospection',
  schema: {
    name: 'extro_rf_tune',
    description: 'RF sense organ — the radio analogue of extro_watch / ' \
                 'extro_verify. Tunes a *running* GQRX instance (remote ' \
                 'control, never launches the GUI), demodulates, measures ' \
                 'signal strength, and samples RDS (PI / PS / RadioText) so ' \
                 'questions like "what\'s playing on 101.1 FM?" get a live ' \
                 'answer. Auto-detects band plan (fm_radio → WFM_ST + RDS). ' \
                 'Returns {ok:, freq:, hz:, strength_dbfs:, demodulator_mode:, ' \
                 'rds:{pi,ps_name,radiotext,station}, now_playing:, station:, ' \
                 'summary:}. On success also observe(category: :rf) so the ' \
                 'EXTROSPECTION prompt block and extro_correlate see it. ' \
                 'Requires GQRX remote control listening (default 7356) + ' \
                 'an SDR attached; fails fast with actionable advice otherwise.',
    parameters: {
      type: 'object',
      properties: {
        freq: {
          type: 'string',
          description: 'Frequency to tune. Free-form: "101.1", "101.1 FM", ' \
                       '"101.1 MHz", "101.100.000", "101100000", "433.92", …'
        },
        host: { type: 'string', description: 'GQRX remote-control host (default 127.0.0.1).' },
        port: { type: 'integer', description: 'GQRX remote-control port (default 7356).' },
        settle_secs: {
          type: 'number',
          description: 'Seconds to sample RDS after tuning (default 8, max 30).'
        },
        rds: {
          type: 'boolean',
          description: 'Force RDS sampling on/off. Default: auto (on for FM ' \
                       'broadcast / band-plans with decoder: :rds).'
        },
        demodulator_mode: {
          type: 'string',
          description: 'Override demod (WFM_ST, WFM, FM, AM, USB, LSB, …). ' \
                       'Default from band-plan / FM range heuristic.'
        },
        bandwidth: {
          type: 'string',
          description: 'Passband e.g. "200.000" (Hz, PWN dotted form). Default from band-plan.'
        },
        record: {
          type: 'boolean',
          default: true,
          description: 'Also observe(category: :rf) so it hits EXTROSPECTION (default true).'
        },
        ttl: {
          type: 'integer',
          description: 'Observation TTL seconds (default 300 — radio content is ephemeral).'
        }
      },
      required: %w[freq]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Extrospection) && PWN::AI::Agent::Extrospection.respond_to?(:rf_tune) },
  handler: lambda { |args|
    o = { freq: args[:freq] }
    o[:host]             = args[:host]             if args[:host]
    o[:port]             = args[:port]             if args[:port]
    o[:settle_secs]      = args[:settle_secs]      if args[:settle_secs]
    o[:rds]              = args[:rds]              if args.key?(:rds)
    o[:demodulator_mode] = args[:demodulator_mode] if args[:demodulator_mode]
    o[:bandwidth]        = args[:bandwidth]        if args[:bandwidth]
    o[:record]           = args[:record]           if args.key?(:record)
    o[:ttl]              = args[:ttl]              if args[:ttl]
    PWN::AI::Agent::Extrospection.rf_tune(o)
  }
)
