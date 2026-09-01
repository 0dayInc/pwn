# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'session_export',
  toolset: 'sessions',
  schema: {
    name: 'session_export',
    description: 'Export a session transcript plus attached artifacts as a tar.gz under ~/.pwn/exports.',
    parameters: {
      type: 'object',
      properties: { session_id: { type: 'string' } },
      required: %w[session_id]
    }
  },
  handler: lambda { |args|
    PWN::Sessions.export(session_id: args[:session_id] || args['session_id'])
  }
)
