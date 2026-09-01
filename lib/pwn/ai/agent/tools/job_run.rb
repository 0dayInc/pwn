# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'job_run',
  toolset: 'terminal',
  schema: {
    name: 'job_run',
    description: 'Start a detached background job (nmap, afl, hashcat). Returns {id, pid, log}.',
    parameters: {
      type: 'object',
      properties: {
        command: { type: 'string' },
        cmd: { type: 'string' },
        tag: { type: 'string' }
      },
      required: %w[command]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::Jobs.start(command: args[:command] || args[:cmd] || args['command'], session_id: args[:tag] || args['tag'])
  }
)
PWN::AI::Agent::Registry.register(
  name: 'job_status',
  toolset: 'terminal',
  schema: {
    name: 'job_status',
    description: 'Poll a job started by job_run.',
    parameters: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: %w[id]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::Jobs.status(id: args[:id] || args['id'])
  }
)
PWN::AI::Agent::Registry.register(
  name: 'job_result',
  toolset: 'terminal',
  schema: {
    name: 'job_result',
    description: 'Fetch log tail and paths for a job_run id.',
    parameters: {
      type: 'object',
      properties: { id: { type: 'string' }, lines: { type: 'integer' } },
      required: %w[id]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::Jobs.result(id: args[:id] || args['id'], lines: args[:lines] || args['lines'])
  }
)
