# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'engagement_open',
  toolset: 'sessions',
  schema: {
    name: 'engagement_open',
    description: 'Open or update an engagement scope document and mark it active.',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string' },
        scope_cidrs: { type: 'array', items: { type: 'string' } },
        scope_domains: { type: 'array', items: { type: 'string' } }
      },
      required: %w[name]
    }
  },
  handler: lambda { |args|
    PWN::AI::Agent::Engagement.open(
      name: args[:name] || args['name'],
      scope_cidrs: args[:scope_cidrs] || args['scope_cidrs'],
      scope_domains: args[:scope_domains] || args['scope_domains']
    )
  }
)
PWN::AI::Agent::Registry.register(
  name: 'engagement_close',
  toolset: 'sessions',
  schema: { name: 'engagement_close', description: 'Clear the active engagement.', parameters: { type: 'object', properties: {} } },
  handler: ->(_args) { PWN::AI::Agent::Engagement.close }
)
PWN::AI::Agent::Registry.register(
  name: 'engagement_status',
  toolset: 'sessions',
  schema: { name: 'engagement_status', description: 'Return the active engagement document.', parameters: { type: 'object', properties: { name: { type: 'string' } } } },
  handler: ->(args) { PWN::AI::Agent::Engagement.status(name: args[:name] || args['name']) }
)
