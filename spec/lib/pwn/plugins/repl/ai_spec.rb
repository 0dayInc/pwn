# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL::AI do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::REPL::AI
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::REPL::AI
    expect(help_response).to respond_to :help
  end

  it 'registers the pwn-ai Pry command' do
    expect(described_class).to respond_to :add_commands
    described_class.add_commands
    expect(Pry::Commands.find_command('pwn-ai')).not_to be_nil
  end

  it 'presents nested command records without Ruby or JSON serialization noise' do
    result = { jobs: [{ id: 'job-1', active: false, result: nil, tags: [], metadata: {} }] }
    expect(PWN::Plugins::REPL.pwn_ai_result_text(value: result)).to eq(
      "jobs:\n  1.\n    id: job-1\n    active: false\n    result: null\n    tags: []\n    metadata: {}"
    )
  end

  it 'decodes root JSON only and preserves multiline, escaped, empty and mixed values' do
    value = { 'text' => "one\n\"two\"\\three\n", 'code' => '{"raw":true}', 'mixed' => [nil, false, 0, '', 'false', [], {}, ['x']] }
    before = Marshal.dump(value)
    text = PWN::Plugins::REPL.pwn_ai_result_text(value: JSON.generate(value))
    expect(text).to include("text: |\n  one\n  \"two\"\\three\n  ", 'code: {"raw":true}', '1. null', '2. false', '3. 0', '4. ""', '5. "false"', '6. []', '7. {}', "8.\n    1. x")
    expect(Marshal.dump(value)).to eq(before)
    ['```json\n{"a":1}\n```', '{invalid', 'prefix {"a":1}', 'false', '"a"'].each do |raw|
      expect(PWN::Plugins::REPL.pwn_ai_result_text(value: raw)).to eq(raw)
    end
    expect(PWN::Plugins::REPL.pwn_ai_result_text(value: '[false,null,{}]')).to eq("1. false\n2. null\n3. {}")
  end

  it 'queues a complete command event instead of one notice per printed line' do
    queue = Queue.new
    output = PWN::Plugins::REPL::AIConsole::EventIO.new(queue)
    PWN::Plugins::REPL.pwn_ai_print_result(value: { a: false, b: nil }, output: output)
    expect(queue.pop).to eq([:command, "a: false\nb: null"])
    expect(queue).to be_empty
  end

  it 'makes empty root command results visible instead of dropping them' do
    { nil => 'null', false => 'false', [] => '[]', {} => '{}', '' => '""', " \n" => '" \\n"' }.each do |value, expected|
      expect(PWN::Plugins::REPL.pwn_ai_result_text(value: value)).to eq(expected)
    end
  end

  it 'redacts secret fields before multiline layout without mutating machine results' do
    record = { account: { password: "first-secret\nsecond-secret", client_secret: 'fixture-credential' }, enabled: false }
    original = Marshal.dump(record)
    [record, JSON.generate(record)].each do |value|
      shown = PWN::Plugins::REPL.pwn_ai_result_text(value: value)
      expect(shown).to include('password: [REDACTED:password:', 'client_secret: [REDACTED:client_secret:', 'enabled: false')
      expect(shown).not_to include('first-secret', 'second-secret', 'fixture-credential')
    end
    expect(Marshal.dump(record)).to eq(original)
  end
end

describe 'menu command result routes' do
  include_context 'pwn tmp sandbox'

  let(:pry) { Pry.new }
  let(:record) { { fixture: 'offline', enabled: false, missing: nil, rows: [{ id: 'sample', labels: [] }] } }

  it 'leases activation, transfers resume ownership and releases on leaving AI mode' do
    first = PWN::Plugins::REPL.pwn_ai_activation_session(pry: pry)
    expect(PWN::Sessions.active?(session_id: first[:id])).to be(true)
    other = PWN::Sessions.create
    PWN::Plugins::REPL.pwn_ai_run_sessions(pry: pry, args: ['resume', other[:id]])
    expect(PWN::Sessions.active?(session_id: first[:id])).to be(false)
    expect(PWN::Sessions.active?(session_id: other[:id])).to be(true)
    PWN::Plugins::REPL.leave_special_mode!(pry: pry)
    expect(PWN::Sessions.active?(session_id: other[:id])).to be(false)
  ensure
    PWN::Sessions.deactivate(lease: pry.config.pwn_ai_session_lease)
  end

  it 'rejects the removed alias and session prefix collisions without switching' do
    pry.config.pwn_ai_session_id = 'unchanged'
    ['/session', '/session list', '/session resume name', '/sessions-extra resume name', '/sessions/resume name'].each do |line|
      expect(PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: line, pry: pry)).to be(false)
      expect(pry.config.pwn_ai_session_id).to eq('unchanged')
    end
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/help', pry: pry) }.to output(a_string_including('/sessions resume').and(a_string_matching(%r{\A(?!.*?/session(?:\s|$))}m))).to_stdout
  end

  it 'resumes by exact Unicode title or id through plural commands and lists both fields' do
    session = PWN::Sessions.create(id: 'resume_title', title: 'Café  "login" repair')
    ['/sessions resume Café  "login" repair', '/sessions resume \'Café  "login" repair\'', '/sessions resume resume_title', '　/sessions　resume　Café  "login" repair　'].each do |line|
      pry.config.pwn_ai_session_id = 'before'
      expect(PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: line, pry: pry)).to be(true)
      expect(pry.config.pwn_ai_session_id).to eq(session[:id])
    end
    ['/sessions list'].each do |line|
      expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: line, pry: pry) }.to output(a_string_including('id: resume_title', 'title: Café  "login" repair')).to_stdout
    end
  end

  it 'renders real dependency paths in the sessions command without hiding the session' do
    allow(Dir).to receive(:home).and_return(@tmp)
    id = '20200101_010203_abcdef12'
    PWN::Sessions.create(id: id)
    dependency = File.join(Dir.home, '.pwn', 'learning.jsonl')
    FileUtils.mkdir_p(File.dirname(dependency))
    File.write(dependency, JSON.generate(session_id: id))
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/sessions list', pry: pry) }.to output(a_string_including("id: #{id}", 'dependencies:', 'referenced by', dependency)).to_stdout
    PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: "/sessions resume #{id}", pry: pry)
    expect(pry.config.pwn_ai_session_id).to eq(id)
  end

  it 'lists and resumes the same seven-word legacy title with stable id fallback on collisions' do
    title = 'One two three four five six seven'
    PWN::Sessions.create(id: 'capped_resume')
    File.write(File.join(PWN::Sessions.sessions_dir, 'capped_resume.meta.json'), JSON.generate(title: "#{title} eight nine", title_source: 'summary'))
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/sessions list', pry: pry) }.to output(a_string_including("title: #{title}\n")).to_stdout
    PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: "/sessions resume '#{title}'", pry: pry)
    expect(pry.config.pwn_ai_session_id).to eq('capped_resume')
    PWN::Sessions.create(id: 'capped_duplicate', title: "#{title} ten")
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: "/sessions resume #{title}", pry: pry) }.to output(a_string_including('NOTICE', 'Ambiguous', 'capped_resume', 'capped_duplicate', '/sessions resume <ID>')).to_stdout
    expect(pry.config.pwn_ai_session_id).to eq('capped_resume')
    PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/sessions resume capped_duplicate', pry: pry)
    expect(pry.config.pwn_ai_session_id).to eq('capped_duplicate')
  end

  it 'does not switch sessions for missing or duplicate titles' do
    %w[duplicate_a duplicate_b].each { |id| PWN::Sessions.create(id: id, title: 'Same title') }
    pry.config.pwn_ai_session_id = 'original'
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/sessions resume Same title', pry: pry) }.to output(a_string_including('NOTICE', 'Ambiguous', 'duplicate_a', 'duplicate_b', '/sessions resume <ID>')).to_stdout
    expect(pry.config.pwn_ai_session_id).to eq('original')
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/sessions resume absent', pry: pry) }.to output(a_string_including('not found')).to_stderr
    expect(pry.config.pwn_ai_session_id).to eq('original')
  end

  it 'preserves the configured Pry output stream for legacy command aliases' do
    PWN::Plugins::REPL::AI.add_commands
    allow(Pry).to receive(:history).and_return(Pry::History.new(file_path: File.join(@tmp, 'alias_history')))
    allow(PWN::Memory).to receive(:recall).and_return(record)
    allow(PWN::Sessions).to receive_messages(list: record, stats: record)
    allow(PWN::Cron).to receive_messages(list: record, run: record)
    ['pwn-ai-memory list', 'pwn-ai-memory recall fixture', 'pwn-ai-sessions list', 'pwn-ai-sessions stats', 'pwn-ai-cron list', 'pwn-ai-cron run fixture'].each do |line|
      output = StringIO.new
      Pry.new(output: output, quiet: true).eval(line)
      expect(output.string).to include("fixture: offline\nenabled: false\nmissing: null")
    end
  end

  it 'formats the complete created cron job rather than interpolating its Hash into prose' do
    allow(PWN::Cron).to receive(:create).and_return(record)
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/cron create hourly fixture', pry: pry) }.to output(/created:\n  fixture: offline\n  enabled: false\n  missing: null/).to_stdout
    PWN::Plugins::REPL::AI.add_commands
    allow(Pry).to receive(:history).and_return(Pry::History.new(file_path: File.join(@tmp, 'create_history')))
    output = StringIO.new
    Pry.new(output: output, quiet: true).eval('pwn-ai-cron create hourly fixture')
    expect(output.string).to include("created:\n  fixture: offline\n  enabled: false\n  missing: null")
  end

  {
    '/cron' => ['PWN::Cron', :list],
    '/cron list' => ['PWN::Cron', :list],
    '/cron run fixture' => ['PWN::Cron', :run],
    '/sessions' => ['PWN::Sessions', :list],
    '/sessions list' => ['PWN::Sessions', :list],
    '/sessions stats' => ['PWN::Sessions', :stats],
    '/memory' => ['PWN::Memory', :recall],
    '/memory list' => ['PWN::Memory', :recall],
    '/memory recall fixture' => ['PWN::Memory', :recall],
    '/learning' => ['PWN::AI::Agent::Learning', :outcomes],
    '/learning list' => ['PWN::AI::Agent::Learning', :outcomes],
    '/learning list --conflicted' => ['PWN::AI::Agent::Learning', :list_conflicted],
    '/learning list conflicted' => ['PWN::AI::Agent::Learning', :list_conflicted],
    '/learning requeue' => ['PWN::AI::Agent::Learning', :requeue_conflicted]
  }.each do |line, (namespace, method)|
    it "formats #{line} through the submitted slash router" do
      allow(Object.const_get(namespace)).to receive(method).and_return(record)
      heading = ['/sessions', '/sessions list'].include?(line) ? "Session dependencies: referenced by these files; text mentions are not links.\n" : ''
      expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: line, pry: pry) }.to output("#{heading}fixture: offline\nenabled: false\nmissing: null\nrows:\n  1.\n    id: sample\n    labels: []\n").to_stdout
    end
  end

  %w[list backends current status ping tools connect disconnect close use].each do |action|
    ['', 'fixture '].each do |backend|
      it "formats /mcp #{backend}#{action} without modifying the broker result" do
        allow(PWN::AI::MCP).to receive(:backends).and_return([{ name: 'fixture' }])
        allow(PWN::AI::MCP).to receive(:invoke).and_return(record)
        expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: "/mcp #{backend}#{action}", pry: pry) }.to output(/fixture: offline\nenabled: false\nmissing: null/).to_stdout
        expect(record[:enabled]).to be(false)
      end
    end
  end

  ['list tools fixture', 'call tool {"option":"5.10"}', 'fixture call tool {"option":"5.10"}', 'fixture'].each do |args|
    it "formats /mcp #{args} including serialized object and array responses" do
      allow(PWN::AI::MCP).to receive(:backends).and_return([{ name: 'fixture' }])
      allow(PWN::AI::MCP).to receive(:invoke).and_return(JSON.generate([record]))
      expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: "/mcp #{args}", pry: pry) }.to output(/1\.\n  fixture: offline\n  enabled: false/).to_stdout
    end
  end

  (PWN::Plugins::REPL::AIConsoleCommands::SWARM - %w[dashboard help]).each do |action|
    it "formats /swarm #{action} through curses and legacy presentation without changing execution" do
      controller = instance_double(PWN::Plugins::REPL::AISwarm::Controller)
      allow(controller).to receive(:execute).and_return(record)
      pry.config.pwn_ai_swarm = controller
      expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: "/swarm #{action}", pry: pry) }.to output(/fixture: offline\nenabled: false/).to_stdout
      console = PWN::Plugins::REPL::AIConsole::Console.new(pry: pry, input: StringIO.new, curses: Curses, getch: nil)
      console.instance_variable_set(:@swarm, controller)
      console.run_swarm("/swarm #{action}")
      expect(console.instance_variable_get(:@timeline).last.take(2)).to eq([:command, PWN::Plugins::REPL.pwn_ai_result_text(value: record)])
    end
  end

  it 'keeps existing skills, model catalogs, help and MCP help human text intact' do
    stub_const('PWN::Skills', { 'fixture-skill' => 'body' })
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/skills list', pry: pry) }.to output("fixture-skill\n").to_stdout
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/skills recall fixture', pry: pry) }.to output("fixture-skill\n").to_stdout
    allow(PWN::Plugins::REPL).to receive(:pwn_ai_engines).and_return(['fixture'])
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/model list', pry: pry) }.to output(%r{pwn-ai /model}).to_stdout
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/help', pry: pry) }.to output(/pwn-ai commands:/).to_stdout
    allow(PWN::AI::MCP).to receive_messages(backends: [{ name: 'fixture' }], current: 'fixture', invoke: { backends: [{ name: 'fixture', constant: 'Offline' }] })
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/mcp help', pry: pry) }.to output(/\* fixture  Offline/).to_stdout
  end
end
