# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'pwn/ai/agent/swarm'

# Multi-agent orchestration tools. These let the PRIMARY pwn-ai agent
# spawn/ask/debate SUB-agents (personas from ~/.pwn/agents.yml), each of
# which is a full PWN::AI::Agent::Loop.run — tool-calling, memory-aware,
# metrics-recorded, learning-reflected. This replaces the legacy pwn-irc
# "N chatbots on inspircd" mechanism with an in-process JSONL bus under
# ~/.pwn/swarm/<id>/, so conversations survive the process and can be
# resumed cross-session by any pwn-ai / PWN::Cron job.

PWN::AI::Agent::Registry.register(
  name: 'agent_list',
  toolset: 'swarm',
  schema: {
    name: 'agent_list',
    description: 'List defined multi-agent personas from ~/.pwn/agents.yml ' \
                 '(name, role summary, engine, toolsets, max_iters). Use ' \
                 'before agent_ask / agent_debate to see who you can ' \
                 'delegate to. Define new ones with agent_spawn.',
    parameters: { type: 'object', properties: {}, required: [] }
  },
  check: -> { defined?(PWN::AI::Agent::Swarm) },
  handler: lambda { |_args|
    PWN::AI::Agent::Swarm.personas.map do |name, p|
      {
        name: name,
        role: p[:role].to_s[0, 200],
        engine: p[:engine],
        toolsets: p[:toolsets],
        max_iters: p[:max_iters]
      }
    end
  }
)

PWN::AI::Agent::Registry.register(
  name: 'agent_spawn',
  toolset: 'swarm',
  schema: {
    name: 'agent_spawn',
    description: 'Define (or overwrite) a persona in ~/.pwn/agents.yml so ' \
                 'it can be used with agent_ask / agent_debate. A persona ' \
                 'is a system-role overlay + toolset allow-list + engine ' \
                 'override. Omit "swarm" from toolsets to prevent that ' \
                 'persona from recursively spawning further sub-agents.',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'snake_case persona name.' },
        role: { type: 'string', description: 'System-role overlay describing this persona.' },
        toolsets: {
          type: 'array', items: { type: 'string' },
          description: 'Registry toolset names this persona may use ' \
                       '(e.g. terminal, pwn, memory, skills, extrospection). ' \
                       'Default: everything except swarm/cron.'
        },
        engine: {
          type: 'string', enum: %w[openai anthropic grok gemini ollama],
          description: 'Override AI engine for this persona (model diversity ' \
                       '= real antagonism). Default: inherit active engine.'
        },
        max_iters: {
          type: 'integer',
          description: 'Per-turn tool-loop cap for this persona (default 25).'
        }
      },
      required: %w[name role]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Swarm) },
  handler: lambda { |args|
    PWN::AI::Agent::Swarm.spawn(
      name: args[:name],
      role: args[:role],
      toolsets: args[:toolsets],
      engine: args[:engine],
      max_iters: args[:max_iters]
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'agent_ask',
  toolset: 'swarm',
  schema: {
    name: 'agent_ask',
    description: 'Run ONE turn of a named persona as a full tool-calling ' \
                 'sub-agent (PWN::AI::Agent::Loop.run under that persona). ' \
                 'The reply comes back to YOU as a tool result. Request + ' \
                 'reply are appended to ~/.pwn/swarm/<swarm_id>/bus.jsonl so ' \
                 'other personas (and future sessions) can see them. ' \
                 'Recursion is depth-capped by PWN::Env[:ai][:agent][:max_depth].',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Persona name (see agent_list).' },
        request: { type: 'string', description: 'What to ask / instruct the persona.' },
        swarm_id: {
          type: 'string',
          description: 'Existing swarm to join (from swarm_list / a prior ' \
                       'agent_ask). Omit to auto-create a new swarm.'
        }
      },
      required: %w[name request]
    }
  },
  max_chars: 32_000,
  check: -> { defined?(PWN::AI::Agent::Swarm) },
  handler: lambda { |args|
    PWN::AI::Agent::Swarm.ask(
      name: args[:name],
      request: args[:request],
      swarm_id: args[:swarm_id]
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'agent_debate',
  toolset: 'swarm',
  schema: {
    name: 'agent_debate',
    description: 'Round-robin an antagonistic debate between 2+ personas. ' \
                 'Each persona sees the swarm bus tail (prior turns) and is ' \
                 'asked to respond/critique/advance. Returns the full ' \
                 'transcript plus swarm_id so you can continue it later. ' \
                 'This is the native replacement for the legacy pwn-irc ' \
                 'multi-agent chat.',
    parameters: {
      type: 'object',
      properties: {
        names: {
          type: 'array', items: { type: 'string' },
          description: '>=2 persona names in speaking order.'
        },
        topic: { type: 'string', description: 'Opening question / claim / target.' },
        rounds: { type: 'integer', default: 2, description: 'Full passes over names.' },
        swarm_id: { type: 'string', description: 'Existing swarm to continue.' }
      },
      required: %w[names topic]
    }
  },
  max_chars: 48_000,
  check: -> { defined?(PWN::AI::Agent::Swarm) },
  handler: lambda { |args|
    PWN::AI::Agent::Swarm.debate(
      names: args[:names],
      topic: args[:topic],
      rounds: args[:rounds],
      swarm_id: args[:swarm_id]
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'agent_broadcast',
  toolset: 'swarm',
  schema: {
    name: 'agent_broadcast',
    description: 'Fan the same request out to multiple personas (default: ' \
                 'all defined) and return {name => reply}. Useful for ' \
                 'ensemble opinions / voting on an approach.',
    parameters: {
      type: 'object',
      properties: {
        request: { type: 'string' },
        names: { type: 'array', items: { type: 'string' } },
        swarm_id: { type: 'string' }
      },
      required: %w[request]
    }
  },
  max_chars: 48_000,
  check: -> { defined?(PWN::AI::Agent::Swarm) },
  handler: lambda { |args|
    PWN::AI::Agent::Swarm.broadcast(
      request: args[:request],
      names: args[:names],
      swarm_id: args[:swarm_id]
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'swarm_bus',
  toolset: 'swarm',
  schema: {
    name: 'swarm_bus',
    description: 'Tail the JSONL message bus for a swarm ' \
                 '(~/.pwn/swarm/<id>/bus.jsonl). Read-side of agent_ask / ' \
                 'agent_debate — use to inspect what personas said in a ' \
                 'prior (or concurrent) session before continuing it.',
    parameters: {
      type: 'object',
      properties: {
        swarm_id: { type: 'string' },
        limit: { type: 'integer', default: 25 }
      },
      required: %w[swarm_id]
    }
  },
  check: -> { defined?(PWN::AI::Agent::Swarm) },
  handler: lambda { |args|
    PWN::AI::Agent::Swarm.bus_tail(
      swarm_id: args[:swarm_id],
      limit: args[:limit] || 25
    )
  }
)

PWN::AI::Agent::Registry.register(
  name: 'swarm_list',
  toolset: 'swarm',
  schema: {
    name: 'swarm_list',
    description: 'List all swarms under ~/.pwn/swarm/ (swarm_id, message ' \
                 'count, mtime). Pick one to resume with agent_ask / ' \
                 'agent_debate(swarm_id:) — this is how cross-session ' \
                 'multi-agent conversations continue without a daemon.',
    parameters: { type: 'object', properties: {}, required: [] }
  },
  check: -> { defined?(PWN::AI::Agent::Swarm) },
  handler: lambda { |_args|
    PWN::AI::Agent::Swarm.list
  }
)
