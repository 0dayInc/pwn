# frozen_string_literal: true

require 'pwn'
require 'pry'
require 'json'
require 'io/console'

work = ARGV.fetch(0)
$stdout.sync = true
PWN::AI::Agent::Loop.define_singleton_method(:run) do |opts|
  if opts[:request] == 'second'
    'second completed'
  else
    Process.spawn(RbConfig.ruby, '-e', 'Process.setsid; File.write(ARGV[0], "ready"); sleep 1; File.write(ARGV[1], "late")', File.join(work, 'ready'), File.join(work, 'late'), out: File::NULL, err: File::NULL)
    loop { sleep 0.1 }
  end
end
begin
  PWN::Plugins::REPL.pwn_ai_run_steerable(request: 'first')
rescue Interrupt
  puts 'CANCELLED'
end
second = PWN::Plugins::REPL.pwn_ai_run_steerable(request: 'second')
sleep 1.2
puts JSON.generate(ready: true, late: File.exist?(File.join(work, 'late')), second: second == 'second completed', tty: $stdin.tty?)
