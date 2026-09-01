# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'intel_lookup',
  toolset: 'pwn',
  schema: {
    name: 'intel_lookup',
    description: 'Look up CVE/CWE/CPE via local intel then searchsploit JSON.',
    parameters: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        cve: { type: 'string' },
        cpe: { type: 'string' }
      }
    }
  },
  handler: lambda { |args|
    q = args[:query] || args['query'] || args[:cve] || args['cve'] || args[:cpe] || args['cpe']
    PWN::Plugins::ExploitDB.search(query: q)
  }
)
