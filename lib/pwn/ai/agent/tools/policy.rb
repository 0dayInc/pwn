# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/ai/agent/policy'

# Expose the live tabular RL controller so the model (and operators)
# can inspect Q / REINFORCE progress without being able to clobber
# the policy from a tool call. Reset stays Ruby-only on purpose.

PWN::AI::Agent::Registry.register(
  name: 'policy_stats',
  toolset: 'policy',
  schema: {
    name: 'policy_stats',
    description: 'R5 — live tabular Q / REINFORCE stats (episodes, states, ' \
                 'mean return, mean |TD|). Advisory controller only; does ' \
                 'not replace TaskSummarizer or plan_first.',
    parameters: { type: 'object', properties: {}, required: [] }
  },
  check: -> { defined?(PWN::AI::Agent::Policy) },
  handler: lambda { |_args|
    PWN::AI::Agent::Policy.stats.merge(evaluate: PWN::AI::Agent::Policy.evaluate(limit: 80))
  }
)

PWN::AI::Agent::Registry.register(
  name: 'policy_evaluate',
  toolset: 'policy',
  schema: {
    name: 'policy_evaluate',
    description: 'R5 — replay stored MDP trajectories against the current Q ' \
                 'table. Returns mean_return, mean |TD error|, and greedy_match. ' \
                 'Does not write weights.',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'integer', description: 'Max episodes to replay (default 80).' }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::AI::Agent::Policy) },
  handler: lambda { |args|
    PWN::AI::Agent::Policy.evaluate(limit: args[:limit] || 80)
  }
)

PWN::AI::Agent::Registry.register(
  name: 'policy_recommend',
  toolset: 'policy',
  schema: {
    name: 'policy_recommend',
    description: 'R5 — ε-greedy pick from the live Q table over a caller-supplied ' \
                 'action list. Advisory: planning still chooses the work; this is ' \
                 'what the learned policy would prefer.',
    parameters: {
      type: 'object',
      properties: {
        actions: {
          type: 'array',
          items: { type: 'string' },
          description: 'Tool names to rank (e.g. shell, pwn_eval).'
        },
        epsilon: { type: 'number', description: 'Explore probability (default 0).' }
      },
      required: %w[actions]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Policy) },
  handler: lambda { |args|
    PWN::AI::Agent::Policy.recommend(
      actions: args[:actions],
      epsilon: args.key?(:epsilon) ? args[:epsilon] : 0.0
    )
  }
)
