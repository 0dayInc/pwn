# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'binary_triage',
  toolset: 'pwn',
  schema: {
    name: 'binary_triage',
    description: 'Triage an ELF/PE/Mach-O binary (format, arch, imports, exports) and spill JSON to ~/.pwn/artifacts.',
    parameters: {
      type: 'object',
      properties: { path: { type: 'string', description: 'Filesystem path of the binary.' } },
      required: %w[path]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::BinaryParser.triage(path: args[:path] || args['path'])
  }
)
