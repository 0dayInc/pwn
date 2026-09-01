# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'decompile',
  toolset: 'pwn',
  schema: {
    name: 'decompile',
    description: 'Decompile a binary via Ghidra analyzeHeadless, or r2 pdg if Ghidra is absent.',
    parameters: {
      type: 'object',
      properties: {
        bin: { type: 'string' },
        path: { type: 'string' },
        project_dir: { type: 'string' }
      },
      required: %w[bin]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::Ghidra.decompile(
      bin: args[:bin] || args[:path] || args['bin'],
      project_dir: args[:project_dir] || args['project_dir']
    )
  }
)
