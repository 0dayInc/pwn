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
    description: 'Recall context for the active session: starts at the previous ' \
                 'assistant response and walks backward through the current ' \
                 'session only (skipping empty/invalid turns), then fills with ' \
                 'matching durable ~/.pwn/memory.json entries (newest first).',
    parameters: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Substring to match against session content / durable keys and values. Omit for all.'
        },
        limit: { type: 'integer', default: 20 },
        session_id: {
          type: 'string',
          description: 'Optional session id (default: active PWN::Env / current session).'
        }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::Memory) },
  handler: lambda { |args|
    PWN::Memory.recall(
      query: args[:query],
      limit: args[:limit] || 20,
      session_id: args[:session_id]
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'memory_forget',
  toolset: 'memory',
  schema: {
    name: 'memory_forget',
    description: 'Delete a persistent memory entry by key. Protected keys (operator_pref_*, process_sop_*, mistake_fix_*, memory_*, category preference) require force:true.',
    parameters: {
      type: 'object',
      properties: {
        key: { type: 'string' },
        force: { type: 'boolean', description: 'Bypass protect policy (default false).' }
      },
      required: %w[key]
    }
  },
  check: -> { defined?(PWN::Memory) },
  handler: lambda { |args|
    PWN::Memory.forget(key: args[:key].to_s.to_sym, force: args[:force] == true)
    { forgotten: args[:key] }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'memory_clear',
  toolset: 'memory',
  schema: {
    name: 'memory_clear',
    description: 'Wipe ALL persistent memory (~/.pwn/memory.json) — every ' \
                 'fact, preference, lesson and env entry. Use only for a ' \
                 'poisoned-context reset. IRREVERSIBLE — must pass ' \
                 'confirm:true.',
    parameters: {
      type: 'object',
      properties: {
        confirm: { type: 'boolean', description: 'Must be true to actually clear.' }
      },
      required: %w[confirm]
    }
  },
  check: -> { defined?(PWN::Memory) },
  handler: lambda { |args|
    raise ArgumentError, 'refusing to clear memory without confirm:true' unless args[:confirm] == true

    before = PWN::Memory.load.keys.length
    PWN::Memory.clear(force: true)
    { cleared: true, entries_removed: before, file: PWN::Memory::MEMORY_FILE }
  }
)

PWN::AI::Agent::Registry.register(
  name: 'memory_lean',
  toolset: 'memory',
  schema: {
    name: 'memory_lean',
    description: 'Drop expired ephemeral session_* memory keys and truncate overlong ' \
                 'values. Never removes operator prefs, process SOPs, or mistake_fix_* ' \
                 'lessons. dry_run:true plans only.',
    parameters: {
      type: 'object',
      properties: {
        dry_run: { type: 'boolean', default: false }
      },
      required: []
    }
  },
  check: -> { defined?(PWN::Memory) && PWN::Memory.respond_to?(:lean!) },
  handler: lambda { |args|
    PWN::Memory.lean!(dry_run: args[:dry_run] ? true : false)
  }
)
