# frozen_string_literal: true

require 'pwn'
require 'json'

native = PWN::AI::Agent::MissionNamespace.method(:native)
PWN::AI::Agent::MissionNamespace.define_singleton_method(:native) do |name, arguments|
  if name == 'unshare'
    lambda { |_flags|
      Fiddle.last_error = Errno::EPERM::Errno
      -1
    }
  else
    native.call(name, arguments)
  end
end
marker = File.join(ARGV.fetch(0), 'must-not-run')
begin
  PWN::Plugins::AISandbox::MissionProcess.new { File.write(marker, 'unsafe') }
rescue PWN::Plugins::AISandbox::NotStarted => e
  error = e.message
end
begin
  Process.waitpid(-1, Process::WNOHANG)
  reaped = false
rescue Errno::ECHILD
  reaped = true
end
puts JSON.generate(blocked: !File.exist?(marker), actionable: error.to_s.include?('enable Linux user/PID namespaces'), reaped: reaped)
