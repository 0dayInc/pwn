# frozen_string_literal: true

require 'pwn/ai/agent/registry'

PWN::AI::Agent::Registry.register(
  name: 'fuzz_campaign',
  toolset: 'pwn',
  schema: {
    name: 'fuzz_campaign',
    description: 'Start, status, stop, or triage an AFL++ campaign via background jobs.',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'start|status|stop|triage|minimize' },
        in_dir: { type: 'string' },
        out_dir: { type: 'string' },
        target: { type: 'string' },
        id: { type: 'string' }
      },
      required: %w[action]
    }
  },
  handler: lambda { |args|
    act = (args[:action] || args['action']).to_s
    case act
    when 'start'
      in_dir = args[:in_dir] || args['in_dir']
      out_dir = args[:out_dir] || args['out_dir']
      target = args[:target] || args['target']
      cmd = "afl-fuzz -i #{in_dir} -o #{out_dir} -- #{target}"
      PWN::Plugins::Jobs.start(command: cmd)
    when 'status'
      row = PWN::Plugins::Jobs.status(id: args[:id] || args['id'])
      out_dir = args[:out_dir] || args['out_dir']
      out_dir ? row.merge(PWN::Plugins::AFLplusplus.parse_stats(out_dir: out_dir)) : row
    when 'stop'
      PWN::Plugins::Jobs.stop(id: args[:id] || args['id'])
    when 'triage'
      PWN::Plugins::AFLplusplus.crash_triage(out_dir: args[:out_dir] || args['out_dir'])
    when 'minimize'
      PWN::Plugins::AFLplusplus.minimize(crash: args[:crash] || args['crash'], out: args[:out] || args['out'], target: args[:target] || args['target'])
    else
      { error: "unknown action #{act}" }
    end
  }
)
