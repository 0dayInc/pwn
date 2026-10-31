# frozen_string_literal: true

require 'pwn'
require 'pry'
require 'curses'
require 'json'

work = ARGV.fetch(0)
PWN::AI::Agent::MissionNamespace.force_exec = true
ENV['PWN_MISSION_FIXTURE_WORK'] = work
ENV['PWN_MISSION_FIXTURE_COMMAND'] = ARGV[1] == 'command' ? '1' : '0'
PWN::AI::Agent::MissionNamespace.bootstrap_requires = [File.expand_path('mission_fixture_preload.rb', __dir__)]
PWN::Env[:ai] = { active: :openai, openai: { model: 'offline' }, agent: {} }
pry = Pry.new
pry.config.pwn_ai_session_id = 'offline-pty'
PWN::Sessions.define_singleton_method(:provisional_title) { |**_opts| nil }
PWN::Sessions.define_singleton_method(:refresh_title) { |**_opts| nil }
console = PWN::Plugins::REPL::AIConsole::Console.new(pry: pry, input: $stdin, curses: Curses, getch: nil)
console.define_singleton_method(:queue_title_update) { |*_args| nil }
console.define_singleton_method(:add) do |type, text|
  super(type, text)
  File.write(File.join(work, 'idle'), 'ready') if text.start_with?('Ready.')
  File.write(File.join(work, 'cancelled'), 'ready') if text.start_with?('Mission cancelled;')
  File.write(File.join(work, 'second'), 'ready') if type == :assistant && text == 'second completed'
end
PWN::AI::Agent::Loop.define_singleton_method(:run) do |opts|
  if opts[:request] == 'second'
    'second completed'
  else
    Process.spawn(RbConfig.ruby, '-e', 'Process.setsid; File.write(ARGV[0], "ready"); sleep 1; File.write(ARGV[1], "late")', File.join(work, 'ready'), File.join(work, 'late'), out: File::NULL, err: File::NULL)
    loop { sleep 0.1 }
  end
end
if ARGV[1] == 'command'
  PWN::Plugins::REPL.define_singleton_method(:pwn_ai_dispatch_slash!) do |**_opts|
    PWN::AI::Agent::Loop.run(request: 'first')
  end
end
console.run
sleep 1.2
puts JSON.generate(ready: !console.busy?, late: File.exist?(File.join(work, 'late')), second: File.exist?(File.join(work, 'second')), tty: $stdin.tty?)
