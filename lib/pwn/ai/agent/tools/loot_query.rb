# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'loot_query',
  toolset: 'pwn',
  schema: {
    name: 'loot_query',
    description: 'Query engagement-scoped encrypted loot metadata without decrypting secrets. Store/ingest/offer can select YubiKey hardware protection; hardware access failures never fall back to software. BasicAuth.encode(host:) auto-offers matching secrets when a service prompts for auth.',
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
        yubikey: {
          type: 'object',
          description: 'Non-secret selector for an already provisioned HMAC-SHA1 slot. Omit for the existing backend; an empty object selects hardware defaults.',
          properties: {
            slot: { type: 'integer', enum: [1, 2] },
            serial: { type: 'string', pattern: '^[0-9]+$' },
            timeout: { type: 'number', exclusiveMinimum: 0 }
          },
          additionalProperties: false
        },
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
