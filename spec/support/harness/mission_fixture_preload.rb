# frozen_string_literal: true

# Test-only, explicit trusted bootstrap for exec-isolated workers.
require 'pwn'
require 'rbconfig'

work = ENV.fetch('PWN_MISSION_FIXTURE_WORK')
raise 'isolated fixture work required' unless work.start_with?("#{ENV.fetch('TMPDIR', '/tmp')}/") || work.start_with?('/tmp/')

PWN::Sessions.define_singleton_method(:provisional_title) { |**_opts| nil }
PWN::Sessions.define_singleton_method(:refresh_title) { |**_opts| nil }
PWN::AI::Agent::Loop.define_singleton_method(:run) do |opts|
  if opts[:request] == 'second'
    'second completed'
  else
    Process.spawn(RbConfig.ruby, '-e', 'Process.setsid; File.write(ARGV[0], "ready"); sleep 1; File.write(ARGV[1], "late")', File.join(work, 'ready'), File.join(work, 'late'), out: File::NULL, err: File::NULL)
    loop { sleep 0.1 }
  end
end
if ENV['PWN_MISSION_FIXTURE_COMMAND'] == '1'
  PWN::Plugins::REPL.define_singleton_method(:pwn_ai_dispatch_slash!) do |**_opts|
    PWN::AI::Agent::Loop.run(request: 'first')
  end
end
