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
