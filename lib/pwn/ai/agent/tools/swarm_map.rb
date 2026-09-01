# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'swarm_map',
  toolset: 'pwn',
  schema: {
    name: 'swarm_map',
    description: 'Fan-out TCP/port map of a CIDR or host list. Sequential when swarm is off.',
    parameters: {
      type: 'object',
      properties: {
        targets: { type: 'string' },
        ports: { type: 'string' }
      },
      required: %w[targets]
    }
  },
  handler: lambda { |args|
    PWN::AI::Agent::Swarm.map_targets(
      targets: args[:targets] || args['targets'],
      ports: args[:ports] || args['ports'] || '80,443'
    )
  }
)
