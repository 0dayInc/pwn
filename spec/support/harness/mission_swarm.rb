# frozen_string_literal: true

require 'pwn'
require 'json'
require 'timeout'

work = ARGV.fetch(0)
PWN::AI::Agent::Swarm.define_singleton_method(:ask) do |opts|
  if opts[:request] == 'second'
    { reply: 'second complete' }
  else
    Process.spawn(RbConfig.ruby, '-e', 'Process.setsid; File.write(ARGV[0], "ready"); sleep 1; File.write(ARGV[1], "late")', File.join(work, 'ready'), File.join(work, 'late'), out: File::NULL, err: File::NULL)
    sleep 30
  end
end
controller = PWN::Plugins::REPL::AISwarm::Controller.new(session_id: 'fixture')
controller.execute(line: '/swarm use fixture')
controller.execute(line: '/swarm dm scout first')
Timeout.timeout(10) { sleep 0.01 until File.exist?(File.join(work, 'ready')) }
controller.cancel_all
ready = !controller.busy?
sleep 1.2
puts JSON.generate(ready: ready, late: File.exist?(File.join(work, 'late')))
