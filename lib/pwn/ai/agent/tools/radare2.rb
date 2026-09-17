# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'r2_functions',
  toolset: 'pwn',
  schema: {
    name: 'r2_functions',
    description: 'Open a binary in r2/rizin (r2pipe) and return parsed aflj function JSON. Pair with r2_disasm for main.',
    parameters: {
      type: 'object',
      properties: {
        bin: { type: 'string', description: 'Filesystem path of the binary.' },
        path: { type: 'string', description: 'Alias for bin.' },
        session: { type: 'string', description: 'Existing r2pipe session id from a prior r2_* call.' },
        backend: { type: 'string', enum: %w[r2 rizin] }
      },
      anyOf: [{ required: %w[bin] }, { required: %w[path] }, { required: %w[session] }]
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    session = args[:session] || PWN::Plugins::Radare2.open(args)
    { session: session, command: 'aflj', functions: PWN::Plugins::Radare2.functions(session: session) }
  }
)
PWN::AI::Agent::Registry.register(
  name: 'r2_disasm',
  toolset: 'pwn',
  schema: {
    name: 'r2_disasm',
    description: 'Return parsed pdfj/pdj disassembly JSON for an address or function (default main) from an r2pipe session.',
    parameters: {
      type: 'object',
      properties: {
        bin: { type: 'string' },
        path: { type: 'string' },
        session: { type: 'string' },
        addr: { type: 'string', description: 'Function, symbol, or 0x address. Defaults to main.' },
        n: { type: 'integer', minimum: 1, maximum: 4096, description: 'If set, use pdj for n instructions; otherwise pdfj.' },
        backend: { type: 'string', enum: %w[r2 rizin] }
      },
      anyOf: [{ required: %w[bin] }, { required: %w[path] }, { required: %w[session] }]
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    session = args[:session] || PWN::Plugins::Radare2.open(args)
    addr = args[:addr]
    addr = 'main' if addr.nil? || addr.to_s.empty?
    { session: session, command: args[:n] ? 'pdj' : 'pdfj', addr: addr,
      disasm: PWN::Plugins::Radare2.disasm(args.merge(session: session, addr: addr)) }
  }
)
