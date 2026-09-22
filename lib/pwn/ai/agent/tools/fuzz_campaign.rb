# frozen_string_literal: true

require 'pwn/ai/agent/registry'
require 'shellwords'

PWN::AI::Agent::Registry.register(
  name: 'fuzz_campaign',
  toolset: 'pwn',
  schema: {
    name: 'fuzz_campaign',
    description: 'AFL++/libFuzzer campaign: corpus, dictionary from binary strings, durable Jobs, crash dedup by backtrace hash, auto PWN-RE-003 triage (GDBMI + binary_triage + exploitdev). Poll job_status; no manual glue.',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'start|status|stop|triage|minimize' },
        engine: { type: 'string', description: 'aflplusplus (default) or libfuzzer' },
        in_dir: { type: 'string' },
        out_dir: { type: 'string' },
        target: { type: 'string' },
        max_runtime: { type: 'integer', minimum: 0 },
        session_id: { type: 'string' },
        cwd: { type: 'string' },
        env: { type: 'object', additionalProperties: { type: 'string' } },
        idempotency_key: { type: 'string' },
        id: { type: 'string' },
        crash: { type: 'string' },
        out: { type: 'string' }
      },
      required: %w[action]
    }
  },
  handler: lambda { |args|
    args = args.transform_keys(&:to_sym)
    act = args[:action].to_s
    case act
    when 'start'
      in_dir = args[:in_dir]
      out_dir = args[:out_dir]
      target = args[:target]
      raise ArgumentError, 'in_dir, out_dir and target are required' if [in_dir, out_dir, target].any? { |value| value.to_s.empty? }

      env = args[:env]
      cmd = PWN::Plugins::AFLplusplus.campaign_command(
        engine: args[:engine] || 'aflplusplus',
        in_dir: in_dir,
        out_dir: out_dir,
        target: target,
        max_runtime: args[:max_runtime],
        cwd: args[:cwd],
        env: env&.transform_keys(&:to_s)
      )
      row = PWN::Plugins::Jobs.start(
        command: cmd,
        max_runtime: args[:max_runtime],
        session_id: args[:session_id] || Thread.current[:pwn_session_id],
        cwd: args[:cwd],
        env: env&.transform_keys(&:to_s),
        idempotency_key: args[:idempotency_key]
      )
      if defined?(PWN::AI::Agent::Mission) && (mid = PWN::AI::Agent::Mission.active_id)
        PWN::AI::Agent::Mission.note_job!(id: mid, job_id: row[:id], idempotent: !args[:idempotency_key].to_s.empty?, log_offset: 0, command: cmd, idempotency_key: args[:idempotency_key])
      end
      row
    when 'status'
      row = PWN::Plugins::Jobs.status(id: args[:id])
      out_dir = args[:out_dir]
      row = row.merge(PWN::Plugins::AFLplusplus.parse_stats(out_dir: out_dir)) if out_dir
      if out_dir
        triage = PWN::Plugins::AFLplusplus.crash_triage(out_dir: out_dir, target: args[:target], handoff: true)
        row = row.merge(triage: triage)
      end
      row
    when 'stop'
      PWN::Plugins::Jobs.stop(id: args[:id])
    when 'triage'
      PWN::Plugins::AFLplusplus.crash_triage(out_dir: args[:out_dir], target: args[:target], handoff: true)
    when 'minimize'
      PWN::Plugins::AFLplusplus.minimize(crash: args[:crash], out: args[:out], target: args[:target])
    else
      { error: "unknown action #{act}" }
    end
  }
)
