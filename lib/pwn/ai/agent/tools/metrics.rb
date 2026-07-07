# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/ai/agent/metrics'

# Direct access to the per-tool telemetry store (~/.pwn/metrics.json).
# `learning_stats` already surfaces a compact metrics blob, but the model
# needs a way to (a) pull the full table without dragging outcome/skill/
# memory counts along, and (b) RESET stale telemetry after a broken tool
# is fixed — otherwise a historical 0 %-success row actively mis-teaches
# tool selection on every future turn.

PWN::AI::Agent::Registry.register(
  name: 'metrics_summary',
  toolset: 'metrics',
  schema: {
    name: 'metrics_summary',
    description: 'Return per-tool telemetry from ~/.pwn/metrics.json ' \
                 '(name, calls, success_rate, avg_duration, last_error, ' \
                 'last_at) sorted by call volume. Lighter-weight than ' \
                 'learning_stats when you only need tool effectiveness.',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'integer', default: 25, description: 'Max tool rows to return.' }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::AI::Agent::Metrics) },
  handler: lambda { |args|
    PWN::AI::Agent::Metrics.summary(limit: args[:limit] || 25)
  }
)

PWN::AI::Agent::Registry.register(
  name: 'metrics_reset',
  toolset: 'metrics',
  schema: {
    name: 'metrics_reset',
    description: 'Wipe ~/.pwn/metrics.json (all per-tool call/success/duration ' \
                 'counters). Use after fixing a previously-broken tool so its ' \
                 'stale 0 %-success rate stops steering the agent away from ' \
                 'it. IRREVERSIBLE — must pass confirm:true.',
    parameters: {
      type: 'object',
      properties: {
        confirm: { type: 'boolean', description: 'Must be true to actually reset.' }
      },
      required: %w[confirm]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Metrics) },
  handler: lambda { |args|
    raise ArgumentError, 'refusing to reset metrics without confirm:true' unless args[:confirm] == true

    before = PWN::AI::Agent::Metrics.summary(limit: 1_000).length
    PWN::AI::Agent::Metrics.reset
    { reset: true, tools_cleared: before, file: PWN::AI::Agent::Metrics::METRICS_FILE }
  }
)
