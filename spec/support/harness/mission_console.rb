# frozen_string_literal: true

require 'pwn'
require 'pry'
require 'json'
require 'timeout'

work = ARGV.fetch(0)
PWN::AI::Agent::MissionNamespace.force_exec = true
ENV['PWN_MISSION_FIXTURE_WORK'] = work
ENV['PWN_MISSION_FIXTURE_COMMAND'] = ARGV[1] == 'command' ? '1' : '0'
PWN::AI::Agent::MissionNamespace.bootstrap_requires = [File.expand_path('mission_fixture_preload.rb', __dir__)]
PWN::Env[:ai] = { active: :openai, openai: { model: 'offline' }, agent: {} }
pry = Pry.new
pry.config.pwn_ai_session_id = 'offline-cancel'
input, tool_input = IO.pipe
console = PWN::Plugins::REPL::AIConsole::Console.new(pry: pry, input: input, curses: nil, getch: nil)
console.instance_variable_set(:@tool_input, tool_input)
PWN::Sessions.define_singleton_method(:provisional_title) { |**_opts| nil }
PWN::Sessions.define_singleton_method(:refresh_title) { |**_opts| nil }
console.define_singleton_method(:queue_title_update) { |*_args| nil }
PWN::AI::Agent::Loop.define_singleton_method(:run) do |opts|
  if opts[:request] == 'second'
    'second completed'
  else
    Process.spawn(RbConfig.ruby, '-e', 'Process.setsid; File.write(ARGV[0], "ready"); sleep 1; File.write(ARGV[1], "late")', File.join(work, 'ready'), File.join(work, 'late'), out: File::NULL, err: File::NULL)
    ARGV[1] == 'command' ? sleep(1.5) : loop { sleep 0.1 }
  end
end
begin
  if ARGV[1] == 'command'
    console.start_request('/mcp test', command: true)
  else
    console.start_request('first')
  end
  generation = console.instance_variable_get(:@mission_generation)
  Timeout.timeout(10) { sleep 0.01 until File.exist?(File.join(work, 'ready')) }
  console.cancel
  console.drain
  ready = !console.busy?
  console.start_request('second')
  console.instance_variable_get(:@events) << [:assistant, 'stale generation', generation]
  Timeout.timeout(10) do
    while console.busy?
      console.drain
      sleep 0.01
    end
  end
  sleep 1.2
  rows = console.instance_variable_get(:@timeline)
  puts JSON.generate(ready: ready, late: File.exist?(File.join(work, 'late')), second: rows.any? { |row| row[1].include?('second completed') }, fenced: rows.none? { |row| row[1].include?('stale generation') })
ensure
  console.stop_worker
end
