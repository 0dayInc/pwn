# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'shellwords'
require 'rbconfig'

PWN::AI::Agent::Registry.register(
  name: 'job_run',
  toolset: 'terminal',
  schema: {
    name: 'job_run',
    description: 'Start durable detached work: fuzzers, full scans, Ghidra analysis or a job graph. Returns a job id immediately; survives agent/session exit. Poll job_status and incrementally read job_tail using next_offset. max_runtime is the supervisor lifetime, NOT a blocking tool timeout; 21600 allows six hours. Reuse idempotency_key on launch retries, never relaunch to poll.',
    parameters: {
      type: 'object',
      properties: {
        command: { type: 'string' },
        cmd: { type: 'string' },
        tag: { type: 'string' },
        session_id: { type: 'string' },
        max_runtime: { type: 'integer', minimum: 0, description: 'Independent wall runtime in seconds; 0 means no runtime limit.' },
        cwd: { type: 'string' },
        env: { type: 'object', additionalProperties: { type: 'string' } },
        idempotency_key: { type: 'string', description: 'Stable launch key reused across retries/sessions to recover the same job.' },
        jobs: { type: 'array' },
        artifact_dir: { type: 'string' }
      },
      anyOf: [{ required: %w[command] }, { required: %w[cmd] }, { required: %w[jobs] }]
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    command = args[:command] || args[:cmd]
    if args[:jobs]
      payload = JSON.generate(jobs: args[:jobs], artifact_dir: args[:artifact_dir])
      script = 'r=PWN::Plugins::Jobs.graph(JSON.parse(ARGV.fetch(0), symbolize_names:true)); puts JSON.generate(r); exit(r[:ok] ? 0 : 1)'
      command = Shellwords.join([RbConfig.ruby, '-I', File.expand_path('../../../..', __dir__), '-rpwn', '-rjson', '-e', script, payload])
    end
    row = PWN::Plugins::Jobs.start(command: command, session_id: args[:session_id] || args[:tag] || Thread.current[:pwn_session_id], max_runtime: args[:max_runtime], cwd: args[:cwd], env: args[:env]&.transform_keys(&:to_s), idempotency_key: args[:idempotency_key])
    if defined?(PWN::AI::Agent::Mission) && (mid = PWN::AI::Agent::Mission.active_id)
      PWN::AI::Agent::Mission.note_job!(id: mid, job_id: row[:id], idempotent: !args[:idempotency_key].to_s.empty?, log_offset: 0, command: command, idempotency_key: args[:idempotency_key])
    end
    row
  }
)
PWN::AI::Agent::Registry.register(
  name: 'job_status',
  toolset: 'terminal',
  schema: {
    name: 'job_status',
    description: 'Poll durable job status by id, including exit/signal. Omit id to rediscover recent jobs from prior sessions. RUNNING is not completion; poll again instead of rerunning job_run.',
    parameters: {
      type: 'object',
      properties: { id: { type: 'string' } }
    }
  },
  handler: lambda { |args|
    id = args[:id] || args['id']
    id ? PWN::Plugins::Jobs.status(id: id) : PWN::Plugins::Jobs.list(limit: 20)
  }
)
PWN::AI::Agent::Registry.register(
  name: 'job_result',
  toolset: 'terminal',
  schema: {
    name: 'job_result',
    description: 'Fetch durable status and a bounded log tail for a job id. Use job_tail for incremental byte-cursor reads.',
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
PWN::AI::Agent::Registry.register(
  name: 'job_tail',
  toolset: 'terminal',
  schema: {
    name: 'job_tail',
    description: 'Read a bounded incremental job log page. Start offset=0, then use next_offset. eof means current log end, not job completion: also poll job_status. Preserve encoding when decoding binary logs.',
    parameters: {
      type: 'object',
      properties: { id: { type: 'string' }, handle: { type: 'string' }, offset: { type: 'integer', minimum: 0 }, length: { type: 'integer', minimum: 1 }, lines: { type: 'integer' } },
      anyOf: [{ required: %w[id] }, { required: %w[handle] }]
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    length = (args[:length] || PWN::AI::Agent::Result.page_length).to_i.clamp(1, PWN::AI::Agent::Result.page_length)
    PWN::Plugins::Jobs.tail(id: args[:id] || args[:handle], offset: args[:offset] || 0, length: length)
  }
)
PWN::AI::Agent::Registry.register(
  name: 'job_kill',
  toolset: 'terminal',
  schema: {
    name: 'job_kill',
    description: 'Request supervised cancellation of a job and its process group. Poll job_status for terminal STOPPED state.',
    parameters: {
      type: 'object',
      properties: { id: { type: 'string' }, handle: { type: 'string' } },
      anyOf: [{ required: %w[id] }, { required: %w[handle] }]
    }
  },
  handler: lambda { |args|
    PWN::Plugins::Jobs.job_kill(id: args[:id] || args[:handle] || args['id'] || args['handle'])
  }
)
