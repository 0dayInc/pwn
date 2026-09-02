# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'pty_open',
  toolset: 'terminal',
  schema: {
    name: 'pty_open',
    description: 'Open a persistent PTY (gdb, r2, ssh, sh). Returns {id, pid}.',
    parameters: {
      type: 'object',
      properties: { cmd: { type: 'string' }, command: { type: 'string' } },
      required: %w[cmd]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::ProcessTube.spawn(cmd: args[:cmd] || args[:command] || args['cmd'])
  }
)
PWN::AI::Agent::Registry.register(
  name: 'pty_send',
  toolset: 'terminal',
  schema: {
    name: 'pty_send',
    description: 'Write a line to a PTY opened by pty_open.',
    parameters: {
      type: 'object',
      properties: { id: { type: 'string' }, line: { type: 'string' }, data: { type: 'string' } },
      required: %w[id]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::ProcessTube.write_line(id: args[:id] || args['id'], line: args[:line] || args[:data] || args['line'])
  }
)
PWN::AI::Agent::Registry.register(
  name: 'pty_read',
  toolset: 'terminal',
  schema: {
    name: 'pty_read',
    description: 'Read a PTY until a string or one line.',
    parameters: {
      type: 'object',
      properties: { id: { type: 'string' }, until: { type: 'string' }, timeout: { type: 'integer' } },
      required: %w[id]
    }
  },
  handler: lambda { |args|
    id = args[:id] || args['id']
    if args[:until] || args['until']
      PWN::Plugins::ProcessTube.recvuntil(id: id, until: args[:until] || args['until'], timeout: args[:timeout])
    else
      PWN::Plugins::ProcessTube.recvline(id: id, timeout: args[:timeout])
    end
  }
)
PWN::AI::Agent::Registry.register(
  name: 'pty_close',
  toolset: 'terminal',
  schema: {
    name: 'pty_close',
    description: 'Close a PTY handle from pty_open.',
    parameters: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: %w[id]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::ProcessTube.close(id: args[:id] || args['id'])
  }
)
PWN::AI::Agent::Registry.register(
  name: 'pty_session',
  toolset: 'terminal',
  schema: {
    name: 'pty_session',
    description: 'Interactive PTY: op spawn|expect|send|stream|close.',
    parameters: {
      type: 'object',
      properties: {
        op: { type: 'string' },
        session_id: { type: 'string' },
        id: { type: 'string' },
        cmd: { type: 'string' },
        command: { type: 'string' },
        pattern: { type: 'string' },
        until: { type: 'string' },
        timeout: { type: 'integer' },
        data: { type: 'string' },
        line: { type: 'string' },
        offset: { type: 'integer' }
      },
      required: %w[op]
    }
  },
  handler: lambda { |args|
    op = (args[:op] || args['op']).to_s
    id = args[:id] || args[:session_id] || args['id'] || args['session_id']
    case op
    when 'spawn'
      PWN::Plugins::ProcessTube.spawn(cmd: args[:cmd] || args[:command] || args['cmd'])
    when 'expect'
      PWN::Plugins::ProcessTube.expect(id: id, until: args[:pattern] || args[:until] || args['pattern'], timeout: args[:timeout])
    when 'send'
      PWN::Plugins::ProcessTube.write_line(id: id, line: args[:data] || args[:line] || args['data'])
    when 'stream'
      PWN::Plugins::ProcessTube.stream(id: id, offset: args[:offset])
    when 'close'
      PWN::Plugins::ProcessTube.close(id: id)
    else
      { error: "unknown op #{op}" }
    end
  }
)
