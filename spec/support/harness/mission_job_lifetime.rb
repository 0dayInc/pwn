# frozen_string_literal: true

require 'pwn'
require 'json'
require 'timeout'

work = ARGV.fetch(0)
ready = File.join(work, 'job-ready')
marker = File.join(work, 'job-running')
reader, writer = IO.pipe
mission = PWN::Plugins::AISandbox::MissionProcess.new do
  reader.close
  PWN::Plugins::AISandbox.protect_call(workspace: work, write_roots: [work]) do
    Process.spawn(RbConfig.ruby, '-e', 'Process.setsid; File.write(ARGV[0], "ready"); sleep 0.3; File.write(ARGV[1], "running"); sleep 30', ready, marker, out: File::NULL, err: File::NULL)
    Timeout.timeout(5) { sleep 0.01 until File.exist?(ready) }
    { started: true }
  end
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
  sleep 0.01 until File.exist?(marker) || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
  writer.puts(JSON.generate(survived_tool: File.exist?(marker)))
  writer.close
end
writer.close
puts reader.read
mission.wait
