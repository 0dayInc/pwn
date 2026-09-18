# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'loot_query',
  toolset: 'pwn',
  schema: {
    name: 'loot_query',
    description: 'Query the engagement-scoped encrypted loot store (creds/tokens/keys with provenance). Use for lateral-movement planning; BasicAuth.encode(host:) auto-offers matching secrets when a service prompts for auth.',
    parameters: {
      type: 'object',
      properties: {
        host: { type: 'string' },
        service: { type: 'string' },
        kind: { type: 'string' },
        engagement: { type: 'string' },
        engagement_id: { type: 'string' },
        finding_id: { type: 'string' },
        op: { type: 'string', enum: %w[query offer ingest store] },
        text: { type: 'string' },
        secret: { type: 'string' },
        username: { type: 'string' },
        where: { type: 'string' },
        source: { type: 'string' },
        label: { type: 'string' }
      }
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    op = (args[:op] || 'query').to_s
    case op
    when 'offer'
      PWN::Plugins::Vault.offer(args)
    when 'ingest'
      PWN::Plugins::Vault.ingest(args.merge(source: args[:source] || 'recon'))
    when 'store'
      PWN::Plugins::Vault.store(args)
    else
      { records: PWN::Plugins::Vault.query(args) }
    end
  }
)
