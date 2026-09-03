# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'debug_session',
  toolset: 'pwn',
  schema: {
    name: 'debug_session',
    description: 'Run a binary under gdb to crash and return typed crash_info.',
    parameters: {
      type: 'object',
      properties: {
        binary: { type: 'string' },
        args: { type: 'array', items: { type: 'string' } },
        script: { type: 'array', items: { type: 'string' } }
      },
      required: %w[binary]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::GDB.debug_session(
      binary: args[:binary] || args['binary'],
      args: args[:args] || args['args'],
      commands: args[:script] || args['script']
    )
  }
)
PWN::AI::Agent::Registry.register(
  name: 'binary_diff',
  toolset: 'pwn',
  schema: {
    name: 'binary_diff',
    description: 'Diff two binaries (radiff2 -C) and rank changed functions.',
    parameters: {
      type: 'object',
      properties: { a: { type: 'string' }, b: { type: 'string' } },
      required: %w[a b]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::BinaryParser.diff(a: args[:a] || args['a'], b: args[:b] || args['b'])
  }
)
PWN::AI::Agent::Registry.register(
  name: 'crash_triage',
  toolset: 'pwn',
  schema: {
    name: 'crash_triage',
    description: 'Dedupe AFL crashes, minimize, debug, and emit findings with PoCs.',
    parameters: {
      type: 'object',
      properties: { campaign: { type: 'string' }, out_dir: { type: 'string' }, target: { type: 'string' } }
    }
  },
  handler: lambda { |args|
    dir = args[:out_dir] || args['out_dir'] || File.join(Dir.home, '.pwn', 'fuzz', (args[:campaign] || args['campaign'] || 'default').to_s)
    PWN::Plugins::AFLplusplus.crash_triage(out_dir: dir)
  }
)
PWN::AI::Agent::Registry.register(
  name: 'capability_request',
  toolset: 'sessions',
  schema: {
    name: 'capability_request',
    description: 'Request a grantable capability (never auto-sudo).',
    parameters: {
      type: 'object',
      properties: { cap: { type: 'string' }, reason: { type: 'string' }, operator_ack: { type: 'boolean' } },
      required: %w[cap]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::Capability.request(
      cap: args[:cap] || args['cap'],
      reason: args[:reason] || args['reason'],
      operator_ack: args[:operator_ack] || args['operator_ack']
    )
  }
)
PWN::AI::Agent::Registry.register(
  name: 'emulate',
  toolset: 'pwn',
  schema: {
    name: 'emulate',
    description: 'Emulate one function (Unicorn) and return registers/memory writes.',
    parameters: {
      type: 'object',
      properties: {
        binary: { type: 'string' },
        addr: { type: 'string' },
        args: { type: 'array' },
        max_insns: { type: 'integer' }
      },
      required: %w[binary addr]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::Emulator.emulate(
      binary: args[:binary] || args['binary'],
      addr: args[:addr] || args['addr'],
      args: args[:args] || args['args'],
      max_insns: args[:max_insns] || args['max_insns']
    )
  }
)
PWN::AI::Agent::Registry.register(
  name: 'detonate',
  toolset: 'pwn',
  schema: {
    name: 'detonate',
    description: 'Run a sample in an isolated container. Refuses if isolation is missing.',
    parameters: {
      type: 'object',
      properties: { path: { type: 'string' }, timeout: { type: 'integer' }, network: { type: 'string' } },
      required: %w[path]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::Detonate.detonate(
      path: args[:path] || args['path'],
      timeout: args[:timeout] || args['timeout'],
      network: args[:network] || args['network']
    )
  }
)
PWN::AI::Agent::Registry.register(
  name: 'budget_status',
  toolset: 'sessions',
  schema: {
    name: 'budget_status',
    description: 'Read-only remaining time/token/mutation budget for this loop.',
    parameters: { type: 'object', properties: {} }
  },
  handler: ->(_args) { PWN::AI::Agent::Loop.budget_status }
)
PWN::AI::Agent::Registry.register(
  name: 'pty_expect',
  toolset: 'terminal',
  schema: {
    name: 'pty_expect',
    description: 'Send optional data and wait for a regex on a PTY with timeout.',
    parameters: {
      type: 'object',
      properties: {
        session: { type: 'string' },
        id: { type: 'string' },
        send: { type: 'string' },
        expect: { type: 'string' },
        timeout: { type: 'integer' }
      }
    }
  },
  handler: lambda { |args|
    id = args[:session] || args[:id] || args['session'] || args['id']
    line = args[:send] || args['send']
    PWN::Plugins::ProcessTube.write_line(id: id, line: line) if line.to_s != ''
    PWN::Plugins::ProcessTube.expect(id: id, until: args[:expect] || args['expect'], timeout: args[:timeout])
  }
)
