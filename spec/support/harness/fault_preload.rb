# frozen_string_literal: true

# Test stimuli only. Forward to real Loop.run with its public runtime/steering
# options. No tool, verifier, checkpoint, compactor or arbiter implementation is
# replaced. This adapter injects steering/runtime controls as an interactive
# caller does; public session selection is tested separately.
require_relative 'fake_provider'
require 'stringio'

fault = JSON.parse(File.read(ENV.fetch('PWN_HARNESS_FIXTURE')), symbolize_names: true)
PWN::AI::Agent::Loop.singleton_class.prepend(Module.new do
  define_method(:run) do |opts = {}|
    root = ENV.fetch('PWN_HARNESS_RUNTIME')
    identity_path = File.join(root, 'identity.json')
    identity = if fault[:resume]
                 JSON.parse(File.read(identity_path), symbolize_names: true)
               else
                 { session_id: opts.fetch(:session_id), request_id: 'offline-fault-request', request: opts.fetch(:request) }
               end
    FileUtils.mkdir_p(root)
    File.write(identity_path, JSON.generate(identity))
    runtime_options = identity.merge(artifact_root: root, resume: !!fault[:resume], trace: false, retrieve: false,
                                     window: fault.fetch(:window, 128_000), enabled_toolsets: ['shell'])
    runtime = PWN::AI::Agent::RequestRuntime.new(runtime_options)
    control = PWN::AI::Agent::Loop::Steering.new(input: $stdin, output: $stderr)
    Thread.current[:pwn_harness_control] = control
    count = 0
    callback = lambda do |*args|
      opts[:on_tool]&.call(*args)
      next unless args[0].to_s == 'shell'

      count += 1
      control.submit(fault.fetch(:steer)) if count == fault[:steer_after_tools]
    end
    super(opts.merge(runtime: runtime, session_id: identity[:session_id], steering: control, on_tool: callback))
  ensure
    if runtime
      observation = { checkpoint: runtime.checkpoint_path, request_id: runtime.request_id, session_id: runtime.session_id,
                      original: runtime.original_request, effective: runtime.request, outcome: runtime.outcome, events: runtime.events }
      File.write(File.join(root, 'runtime-observed.json'), JSON.pretty_generate(observation))
    end
    Thread.current[:pwn_harness_control] = nil
  end
end)
