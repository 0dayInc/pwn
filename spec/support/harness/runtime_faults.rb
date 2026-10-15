# frozen_string_literal: true

# Component contract fixtures, not an end-to-end model benchmark.
require 'json'
require 'fileutils'
require 'tmpdir'
require 'stringio'
require 'timeout'
raise 'temporary HOME required' unless Dir.home.start_with?('/tmp/')

require 'pwn'

root = ARGV.fetch(0)
FileUtils.mkdir_p(root)
rows = []
cap_error = Class.new(Exception) # rubocop:disable Lint/InheritException -- resource cap must escape ordinary provider retry rescues
probe = lambda do |name, &body|
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  observations = Timeout.timeout(10, cap_error) { body.call }
  rows << { id: name, outcome: observations.fetch(:passed) ? 'PASS' : 'FAIL', observations: observations,
            latency_seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
            scope: 'component contract with scripted provider; not Loop.run integration', tokens: nil, cost: nil }
rescue cap_error
  rows << { id: name, outcome: 'INCOMPLETE', reason: 'component wall budget', tokens: nil, cost: nil }
rescue StandardError => e
  rows << { id: name, outcome: 'ERROR', error: "#{e.class}: #{e.message}", tokens: nil, cost: nil }
end
runtime = PWN::AI::Agent::RequestRuntime
options = { request: 'Create original.txt and verify it.', session_id: 'fault-fixture', request_id: 'fixed-request',
            artifact_root: root, trace: false, retrieve: false, window: 200 }
probe.call('compaction-preserves-goal-and-steering') do
  owner = runtime.new(options)
  owner.amend!(instruction: 'Also write latest.txt.')
  messages = [{ role: 'user', content: owner.original_request }]
  20.times { messages << { role: 'assistant', content: 'older context ' * 100 } }
  messages << { role: 'user', content: 'Also write latest.txt.' }
  prepared = nil
  owner.call(messages: messages, tools: []) do |wire, _route|
    prepared = wire
    { role: 'assistant', content: 'fixture response' }
  end
  text = JSON.generate(prepared)
  { passed: text.include?('Create original.txt') && text.include?('Also write latest.txt.') && prepared.length < messages.length,
    input_messages: messages.length, output_messages: prepared.length,
    request: owner.request, original_request: owner.original_request }
end
probe.call('resource-cap-checkpoint-recovery') do
  owner = runtime.new(options.merge(resume: true))
  owner.finish!(status: 'incomplete', unmet: ['runtime budget'])
  resumed = runtime.new(options.merge(resume: true))
  { passed: resumed.outcome[:status] == 'incomplete' && resumed.original_request == options[:request] && resumed.request.include?('latest.txt'),
    outcome: resumed.outcome, checkpoint: resumed.checkpoint_path,
    effects_reexecuted: 0, note: 'Restoration only, does not resume side effects or assert idempotent tool replay.' }
end
probe.call('retry-provider-fallback-before-effects') do
  profiles = PWN::AI::Agent::Profiles.new(profiles: {
                                            first: { provider: :openai, model: 'fixture', fallback: ['second'] },
                                            second: { provider: :openai, model: 'fixture' }
                                          })
  calls = []
  result = profiles.call(name: 'first') do |route|
    calls << route[:name]
    raise EOFError, 'fixture transport failure' if route[:name] == 'first'

    :response
  end
  effect = File.join(root, 'retry-effect.txt')
  File.write(effect, 'one observed effect') if result == :response
  { passed: calls == %w[first second] && File.read(effect) == 'one observed effect', provider_calls: calls.length,
    repeated_effects: 0, note: 'Fallback contract only, not same-provider HTTP retry or post-effect retry safety.' }
end
probe.call('cancel-blocked-provider') do
  input, writer = IO.pipe
  control = PWN::AI::Agent::Loop::Steering.new(input: input, output: StringIO.new)
  entered = Queue.new
  provider = nil
  canceller = Thread.new do
    entered.pop
    control.request_model_cancel
  end
  result = control.model(messages: []) do
    provider = Thread.current
    entered << true
    sleep 60
    :stale
  end
  canceller.join
  provider.join(1)
  { passed: result.nil? && !provider.alive?, stale_result_released: result == :stale, provider_alive: provider.alive? }
ensure
  canceller&.kill if canceller&.alive?
  provider&.kill if provider&.alive?
  input&.close
  writer&.close
end
puts JSON.pretty_generate(schema: 'pwn-runtime-fault-fixtures-v1', results: rows)
exit(rows.all? { |row| row[:outcome] == 'PASS' } ? 0 : 1)
