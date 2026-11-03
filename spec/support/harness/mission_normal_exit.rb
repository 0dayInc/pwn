# frozen_string_literal: true

require 'pwn'
require 'json'
require 'timeout'

root = ARGV.fetch(0)
ready = File.join(root, 'detached-ready')
late = File.join(root, 'detached-late')
unrelated = Process.spawn(RbConfig.ruby, '-e', 'sleep 30', out: File::NULL, err: File::NULL)
begin
  mission = PWN::Plugins::AISandbox::MissionProcess.new do
    fork do
      Process.setsid
      fork do
        File.write(ready, File.read('/proc/self/stat').split.first)
        sleep 1
        File.write(late, 'late')
        exit!
      end
      exit!
    end
    Timeout.timeout(5) { sleep 0.01 until File.exist?(ready) }
  end
  mission.wait
  reaped = !File.exist?("/proc/#{File.read(ready)}")
  sleep 1.2
  preserved = Process.waitpid(unrelated, Process::WNOHANG).nil?
  puts JSON.generate(reaped: reaped, late: File.exist?(late), unrelated: preserved)
ensure
  mission&.close
  Process.kill('KILL', unrelated)
  Process.wait(unrelated)
end
