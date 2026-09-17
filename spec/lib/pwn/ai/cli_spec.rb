# frozen_string_literal: true

require 'spec_helper'
require 'yaml'
require 'open3'
require 'tmpdir'

RSpec.describe 'PWN::AI::CLI' do
  before { require 'pwn/ai/cli' }

  it 'parses explicit actions and preserves path spelling' do
    expect(PWN::AI::CLI.parse(argv: ['--analyze', './a b', '--ai', 'explain'])).to include(analyze: './a b', ai: 'explain')
    expect(PWN::AI::CLI.parse(argv: ['--replay', 'session-1'])).to include(replay: 'session-1')
    expect(PWN::AI::CLI.parse(argv: ['--rerun', 'session-1'])).to include(rerun: 'session-1')
  end

  it 'rejects ambiguous actions and stray positional arguments' do
    [%w[--replay one --rerun two], %w[--analyze file --replay one], %w[--replay one --ai prompt], ['stray']].each do |argv|
      expect { PWN::AI::CLI.parse(argv: argv) }.to raise_error(OptionParser::ParseError)
    end
  end

  it 'replays a real saved trace without configuration or tool execution' do
    require 'pwn/session_trace'
    Dir.mktmpdir do |root|
      allow(PWN::Sessions).to receive(:sessions_dir).and_return(root)
      PWN::SessionTrace.append(session_id: 'cli-fixture', event: 'request', data: { content: 'saved evidence' })
      expect(PWN::Config).not_to receive(:refresh_env)
      out = StringIO.new
      expect(PWN::AI::CLI.run(argv: ['--replay', 'cli-fixture'], output: out)).to eq(0)
      expect(JSON.parse(out.string)['data']['content']).to eq('saved evidence')
    end
  end

  it 'ingests binary evidence before passing the same session to the one-shot loop' do
    require 'pwn/ai/context'
    Dir.mktmpdir do |root|
      source = File.join(root, 'sample')
      FileUtils.cp('/bin/true', source)
      allow(PWN::Sessions).to receive(:sessions_dir).and_return(root)
      allow(PWN::Config).to receive(:refresh_env)
      allow(PWN::AI::Context).to receive(:ingestion_db_path).and_return(File.join(root, 'evidence.db'))
      allow_any_instance_of(Net::HTTP).to receive(:request).and_raise(Errno::ECONNREFUSED)
      expect(PWN::AI::Agent::Loop).to receive(:run) do |args|
        db = SQLite3::Database.new(File.join(root, 'evidence.db'))
        expect(db.get_first_value('SELECT count(*) FROM chunks')).to be > 0
        db.close
        expect(File.file?(File.join(root, "#{args[:session_id]}.jsonl"))).to be(true)
        expect(args[:request]).to eq('explain')
        'fixture answer'
      end
      output = StringIO.new
      expect(PWN::AI::CLI.run(argv: ['--analyze', source, '--ai', 'explain'], output: output)).to eq(0)
      expect(output.string).to include('fixture answer')
    end
  end

  it 'starts the interactive AI REPL using the pre-ingested session' do
    allow(PWN::Config).to receive(:refresh_env)
    allow(PWN::Sessions).to receive(:create).and_return(id: 'cli-interactive')
    expect(PWN::Plugins::REPL).to receive(:start).with(ai_session_id: 'cli-interactive')
    expect(PWN::AI::CLI.run(argv: [])).to eq(0)
  end

  it 'reruns a saved harmless tool inside bubblewrap without loading credentials' do
    require 'pwn/session_trace'
    Dir.mktmpdir do |root|
      allow(PWN::Sessions).to receive(:sessions_dir).and_return(root)
      PWN::SessionTrace.append(session_id: 'cli-rerun', event: 'tool_call', data: { name: 'shell', arguments: { command: 'printf isolated-fixture' } })
      expect(PWN::Config).not_to receive(:refresh_env)
      out = StringIO.new
      expect(PWN::AI::CLI.run(argv: ['--rerun', 'cli-rerun'], output: out)).to eq(0)
      expect(JSON.parse(out.string)['results'].first['stdout']).to eq('isolated-fixture')
    end
  end

  it 'loads provider autoloads when required as the standalone entrypoint' do
    output, status = Open3.capture2e('ruby', '-Ilib', '-rpwn/ai/cli', '-e', 'abort "Context missing" unless PWN::AI.const_defined?(:Context)')
    expect(status.success?).to be(true), output
  end

  it 'returns failure when an isolated rerun tool exits unsuccessfully' do
    require 'pwn/session_trace'
    Dir.mktmpdir do |root|
      allow(PWN::Sessions).to receive(:sessions_dir).and_return(root)
      PWN::SessionTrace.append(session_id: 'cli-failure', event: 'tool_call', data: { name: 'shell', arguments: { command: 'exit 7' } })
      expect(PWN::AI::CLI.run(argv: ['--rerun', 'cli-failure'], output: StringIO.new)).to eq(1)
    end
  end

  it 'documents the Ruby helper API' do
    expect { PWN::AI::CLI.help }.to output(/\.parse.*\.run.*\.authors/m).to_stdout
  end

  it 'emits a YAML DAG for --plan-only without running the agent loop' do
    expect(PWN::AI::Agent::Loop).not_to receive(:run)
    expect(PWN::AI::Agent::Dispatch).not_to receive(:call)
    out = StringIO.new
    expect(PWN::AI::CLI.run(argv: ['--plan-only', '--ai', 'echo one then echo two'], output: out)).to eq(0)
    dag = YAML.safe_load(out.string)
    expect(dag['steps'].length).to be >= 2
    expect(dag['steps'].first).to include('tool', 'args', 'side_effect', 'dependencies')
  end

  it 'prints executable help without reading or creating a vault' do
    Dir.mktmpdir do |home|
      output, status = Open3.capture2e({ 'HOME' => home }, 'ruby', '-Ilib', 'bin/pwn-ai', '--help')
      expect(status.success?).to be(true), output
      expect(output).to include('--analyze', '--replay', '--rerun', '--plan-only', '--resume')
      expect(Dir.children(home)).to eq([])
    end
  end
end
