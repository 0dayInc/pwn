# frozen_string_literal: true

require 'pwn/ai/agent/registry'

# Thin wrappers around PWN::Memory so the model can WRITE to the durable
# store, not just read what PromptBuilder pasted in.

PWN::AI::Agent::Registry.register(
  name: 'memory_remember',
  toolset: 'memory',
  schema: {
    name: 'memory_remember',
    description: 'Save a durable fact, preference, or lesson to persistent ' \
                 'memory (~/.pwn/memory.json). Re-injected into the system ' \
                 'prompt of every future pwn-ai session.',
    parameters: {
      type: 'object',
      properties: {
        key: { type: 'string', description: 'Short unique identifier for this memory.' },
        value: { type: 'string', description: 'The fact / preference / lesson to remember.' },
        category: { type: 'string', enum: %w[fact preference lesson env], default: 'fact' }
      },
      required: %w[key value]
    }
  },
  check: -> { defined?(PWN::Memory) },
  handler: lambda { |args|
    PWN::Memory.remember(
      key: args[:key].to_s.to_sym,
      value: args[:value],
      category: (args[:category] || 'fact').to_sym
    )
    { saved: true, key: args[:key], total: PWN::Memory.load.keys.length }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'memory_recall',
  toolset: 'memory',
  schema: {
    name: 'memory_recall',
    description: 'Search persistent memory for entries matching a substring query.',
    parameters: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Substring to match against keys and values. Omit for all.' },
        limit: { type: 'integer', default: 20 }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::Memory) },
  handler: lambda { |args|
    PWN::Memory.recall(query: args[:query], limit: args[:limit] || 20)
  }
)

PWN::AI::Agent::Registry.register(
  name: 'memory_forget',
  toolset: 'memory',
  schema: {
    name: 'memory_forget',
    description: 'Delete a persistent memory entry by key.',
    parameters: {
      type: 'object',
      properties: { key: { type: 'string' } },
      required: %w[key]
    }
  },
  check: -> { defined?(PWN::Memory) },
  handler: lambda { |args|
    PWN::Memory.forget(key: args[:key].to_s.to_sym)
    { forgotten: args[:key] }
  }
)
