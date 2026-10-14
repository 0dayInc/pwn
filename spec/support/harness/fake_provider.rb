# frozen_string_literal: true

# Test-only preload: never selected by the production CLI or configuration.
require 'json'
require 'pwn'
require 'net/http'
require 'socket'

raise 'isolated HOME required' unless Dir.home.start_with?('/tmp/')
raise 'fixture required' unless ENV['PWN_HARNESS_FIXTURE']

# Defense in depth: no provider HTTP/socket work in this offline lane.
Net::HTTP.prepend(Module.new do
  def connect
    raise 'network forbidden by offline harness'
  end
end)
TCPSocket.singleton_class.prepend(Module.new do
  def new(*)
    raise 'network forbidden by offline harness'
  end
end)

fixture = JSON.parse(File.read(ENV.fetch('PWN_HARNESS_FIXTURE')), symbolize_names: true)
srand(fixture.fetch(:seed, 0))
PWN::Env[:ai] = {
  active: :openai, module_reflection: false,
  openai: { model: 'offline-scripted-v1', reasoning_effort: 'none' },
  agent: { max_iters: 6, task_summary: false, task_summary_llm: false,
           auto_introspect: false, auto_extrospect: false, policy: false,
           toolsets: fixture.fetch(:toolsets, ['shell']) }
}
PWN::Env[:ai][:agent].merge!(fixture.fetch(:agent, {}))
PWN::Config.define_singleton_method(:refresh_env) { |*_args| PWN::Env }
# Observe the real dispatch return, never parse assistant text as host evidence.
PWN::AI::Agent::Dispatch.singleton_class.prepend(Module.new do
  def call(opts = {})
    result = super
    File.open("#{ENV.fetch('PWN_HARNESS_EVENTS')}.tools", 'a') do |io|
      io.puts(JSON.generate(tool_call: opts[:tool_call], result: JSON.parse(result)))
    end
    result
  end
end)
provider = PWN::AI::OpenAI
calls = 0
provider.define_singleton_method(:chat_with_tools) do |opts = {}|
  calls += 1
  row = fixture.fetch(:responses)[calls - 1]
  raise "fixture exhausted at provider call #{calls}" unless row

  File.open(ENV.fetch('PWN_HARNESS_EVENTS'), 'a') do |io|
    io.puts(JSON.generate(event: 'provider_call', call: calls, pid: Process.pid,
                          swarm_depth: Thread.current[:pwn_swarm_depth].to_i,
                          messages: opts[:messages], response: row))
  end
  raise EOFError, 'offline injected transport disconnect' if row[:fault] == 'retry'

  exit!(73) if row[:fault] == 'crash'
  if row[:fault] == 'resource_cap'
    File.write(ENV.fetch('PWN_HARNESS_CAP_READY'), 'ready')
    sleep 60
  end
  if row[:fault] == 'cancel'
    control = Thread.current[:pwn_harness_control]
    raise 'missing request steering control' unless control

    canceller = Thread.new { control.submit('cancel') }
    begin
      sleep 60
    ensure
      canceller.join
    end
  end
  { choices: [{ message: row }] }
end
provider.define_singleton_method(:chat) { |*_args| raise 'unexpected text-only provider path' }
at_exit do
  File.write(ENV.fetch('PWN_HARNESS_FINGERPRINT'), JSON.pretty_generate(PWN::RuntimeFingerprint.report))
end
