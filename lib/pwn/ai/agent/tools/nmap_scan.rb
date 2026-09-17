# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'nmap_scan',
  toolset: 'pwn',
  schema: {
    name: 'nmap_scan',
    description: 'Ingest nmap XML into the engagement store (hosts, services, scripts) and return diff vs last scan. since=yesterday answers what changed since yesterday in one call.',
    parameters: {
      type: 'object',
      properties: {
        xml: { type: 'string', description: 'Path to nmap XML (ingest).' },
        xml_file: { type: 'string' },
        since: { type: 'string', description: 'yesterday | last-scan | ISO8601. Omit xml to only query the diff.' },
        engagement: { type: 'string' },
        override: { type: 'boolean' },
        at: { type: 'string' }
      }
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    xml = args[:xml] || args[:xml_file]
    if xml.to_s.empty?
      PWN::Plugins::NmapIt.changes(since: args[:since] || 'yesterday', engagement: args[:engagement])
    else
      PWN::Plugins::NmapIt.scan(xml: xml, engagement: args[:engagement], override: args[:override], at: args[:at])
    end
  }
)
