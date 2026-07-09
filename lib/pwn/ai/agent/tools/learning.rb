# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/ai/agent/learning'
require 'pwn/ai/agent/metrics'

# Expose the self-improvement engine to the model so it can actively
# participate in the learning loop: log outcomes, trigger reflection,
# promote successful workflows into reusable skills, and inspect its own
# effectiveness metrics.

PWN::AI::Agent::Registry.register(
  name: 'learning_note_outcome',
  toolset: 'learning',
  schema: {
    name: 'learning_note_outcome',
    description: 'Record the outcome of a task attempt so future pwn-ai ' \
                 'runs learn from it. Successes reinforce approaches; ' \
                 'failures become avoidance lessons injected into every ' \
                 'subsequent system prompt.',
    parameters: {
      type: 'object',
      properties: {
        task: { type: 'string', description: 'Short description of what was attempted.' },
        success: { type: 'boolean', description: 'Did the attempt achieve its goal?' },
        details: { type: 'string', description: 'Evidence, error text, or notes.' },
        tags: { type: 'array', items: { type: 'string' } }
      },
      required: %w[task success]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Learning) },
  handler: lambda { |args|
    PWN::AI::Agent::Learning.note_outcome(
      task: args[:task],
      success: args[:success],
      details: args[:details],
      tags: args[:tags]
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'learning_reflect',
  toolset: 'learning',
  schema: {
    name: 'learning_reflect',
    description: 'Analyse a completed session transcript and persist up to ' \
                 '5 durable lessons into PWN::Memory. Uses LLM introspection ' \
                 'when enabled, otherwise a heuristic extractor.',
    parameters: {
      type: 'object',
      properties: {
        session_id: { type: 'string', description: 'PWN::Sessions id to analyse.' },
        dry_run: { type: 'boolean', default: false }
      },
      required: %w[session_id]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Learning) },
  handler: lambda { |args|
    PWN::AI::Agent::Learning.reflect(
      session_id: args[:session_id],
      dry_run: args[:dry_run]
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'learning_distill_skill',
  toolset: 'learning',
  schema: {
    name: 'learning_distill_skill',
    description: 'Promote a successful workflow into a reusable skill under ' \
                 '~/.pwn/skills so it appears in every future system prompt.',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'snake_case skill name.' },
        session_id: { type: 'string', description: 'Session to mine for the procedure.' },
        content: { type: 'string', description: 'Explicit markdown body (overrides session mining).' },
        references: { type: 'array', items: { type: 'string' }, description: 'Optional URLs / CWE / CVE / ATT&CK / NIST references.' }
      },
      required: %w[name]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Learning) },
  handler: lambda { |args|
    PWN::AI::Agent::Learning.distill_skill(
      name: args[:name],
      session_id: args[:session_id],
      content: args[:content],
      references: args[:references]
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'learning_stats',
  toolset: 'learning',
  schema: {
    name: 'learning_stats',
    description: 'Return self-effectiveness metrics: outcome success rate, ' \
                 'skills known, memory size, and per-tool telemetry.',
    parameters: { type: 'object', properties: {}, required: [] }
  },
  check: -> { defined?(PWN::AI::Agent::Learning) },
  handler: lambda { |_args|
    PWN::AI::Agent::Learning.stats.merge(
      tool_metrics: PWN::AI::Agent::Metrics.summary(limit: 10)
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'learning_outcomes',
  toolset: 'learning',
  schema: {
    name: 'learning_outcomes',
    description: 'Query recorded task outcomes from ~/.pwn/learning.jsonl ' \
                 '(the read-side of learning_note_outcome). Filter by ' \
                 'success and/or tag substring; returns newest-first.',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'integer', default: 50, description: 'Max entries returned newest-first.' },
        success: { type: 'boolean', description: 'Filter: only successes (true) or only failures (false). Omit for both.' },
        tag: { type: 'string', description: 'Filter: substring match against outcome tags.' }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::AI::Agent::Learning) },
  handler: lambda { |args|
    o = { limit: args[:limit] || 50 }
    o[:success] = args[:success] if args.key?(:success)
    o[:tag]     = args[:tag]     if args.key?(:tag)
    PWN::AI::Agent::Learning.outcomes(o)
  }
)

PWN::AI::Agent::Registry.register(
  name: 'learning_consolidate',
  toolset: 'learning',
  schema: {
    name: 'learning_consolidate',
    description: 'Deduplicate near-identical PWN::Memory lesson entries and ' \
                 'prune the oldest ones once max_entries is exceeded, so the ' \
                 'injected MEMORY block in every system prompt stays ' \
                 'high-signal. Returns { removed:, remaining: }.',
    parameters: {
      type: 'object',
      properties: {
        max_entries: { type: 'integer', default: 200, description: 'Hard cap on PWN::Memory size after consolidation.' }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::AI::Agent::Learning) },
  handler: lambda { |args|
    PWN::AI::Agent::Learning.consolidate(max_entries: args[:max_entries])
  }
)

PWN::AI::Agent::Registry.register(
  name: 'learning_reset',
  toolset: 'learning',
  schema: {
    name: 'learning_reset',
    description: 'Wipe ~/.pwn/learning.jsonl (all recorded task outcomes and ' \
                 'their success_rate). Use for a clean slate after major ' \
                 'refactors or when dev-experiment noise has polluted the ' \
                 'outcome history. IRREVERSIBLE — must pass confirm:true.',
    parameters: {
      type: 'object',
      properties: {
        confirm: { type: 'boolean', description: 'Must be true to actually reset.' }
      },
      required: %w[confirm]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Learning) },
  handler: lambda { |args|
    raise ArgumentError, 'refusing to reset learning without confirm:true' unless args[:confirm] == true

    before = PWN::AI::Agent::Learning.outcomes(limit: 100_000).length
    PWN::AI::Agent::Learning.reset
    { reset: true, outcomes_cleared: before, file: PWN::AI::Agent::Learning::LEARNING_FILE }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'learning_auto_introspect_toggle',
  toolset: 'learning',
  schema: {
    name: 'learning_auto_introspect_toggle',
    description: 'Enable/disable end-of-run auto-reflection ' \
                 '(PWN::Env[:ai][:agent][:auto_introspect]). When enabled, ' \
                 'Loop.run calls Learning.auto_introspect on the session after ' \
                 'every final answer. Disable during noisy fuzzing loops; ' \
                 're-enable for the summary turn. Omit `enabled` to just ' \
                 'read the current state.',
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
    prev = ai[:agent][:auto_introspect] ? true : false
    ai[:agent][:auto_introspect] = (args[:enabled] ? true : false) if args.key?(:enabled)
    { previous: prev, current: ai[:agent][:auto_introspect] ? true : false }
  }
)
