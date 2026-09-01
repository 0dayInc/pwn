# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'artifacts_list',
  toolset: 'sessions',
  schema: {
    name: 'artifacts_list',
    description: 'List loot under ~/.pwn/artifacts for a session.',
    parameters: {
      type: 'object',
      properties: { session_id: { type: 'string' } }
    }
  },
  handler: lambda { |args|
    PWN::Plugins::ArtifactRegistry.list(session_id: args[:session_id] || args['session_id'] || 'default')
  }
)
PWN::AI::Agent::Registry.register(
  name: 'artifacts_get',
  toolset: 'sessions',
  schema: {
    name: 'artifacts_get',
    description: 'Read an artifact by path (sha256 + body cap).',
    parameters: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: %w[path]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::ArtifactRegistry.get(path: args[:path] || args['path'])
  }
)
