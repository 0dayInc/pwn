# frozen_string_literal: true

require 'pwn'
require 'json'
require 'rbconfig'

work = ARGV.fetch(0)
cancelled = false
runtime = PWN::AI::Agent::RequestRuntime.new(request: 'Create a report', session_id: 'cancelboundary', artifact_root: File.join(Dir.home, 'state'), trace: false, retrieve: false, cancel: -> { cancelled })
Thread.current[:pwn_request_runtime] = runtime
ready = File.join(PWN::Plugins::AISandbox.workspace, 'descendant.pid')
marker = File.join(PWN::Plugins::AISandbox.workspace, 'post-cancel-write')
PWN::AI::Agent::Registry.register(name: 'cancel_boundary_fixture', toolset: 'fixture', schema: { name: 'cancel_boundary_fixture', parameters: { type: 'object' } }, handler: lambda { |_args|
  Process.spawn(RbConfig.ruby, '-e', 'Process.setsid; File.write(ARGV[0], File.read("/proc/self/stat").split.first); sleep 2; File.write(ARGV[1], "late")', ready, marker, in: File::NULL, out: File::NULL, err: File::NULL, close_others: true)
  sleep 30
})
trigger = Thread.new do
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15
  sleep 0.01 until File.exist?(ready) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
  cancelled = true
end
begin
  PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'cancel_boundary_fixture', arguments: '{}' } })
rescue Interrupt
  returned = true
end
trigger.join
reaped = File.exist?(ready) && !File.exist?("/proc/#{File.read(ready)}")
sleep 2.2
puts JSON.generate(cancelled: returned == true, descendant_started: File.exist?(ready), reaped: reaped, post_cancel_write: File.exist?(marker))
