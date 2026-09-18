# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'binary_triage',
  toolset: 'pwn',
  schema: {
    name: 'binary_triage',
    description: 'Triage an ELF/PE/Mach-O binary into one JSON object: type, arch, linking, NX/PIE/RELRO/canary/CFI, imports/exports, interesting strings, section entropy, packer heuristics. Persists to the artifact store.',
    parameters: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Filesystem path of the binary.' },
        session_id: { type: 'string', description: 'Artifact session id (defaults to triage).' }
      },
      required: %w[path]
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    PWN::Plugins::BinaryParser.triage(path: args[:path], session_id: args[:session_id] || args[:session] || 'triage')
  }
)
