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

  it 'evaluates two frozen offline suites without loading configuration or running the loop' do
    Dir.mktmpdir('pwn-cli-policy-', '/tmp') do |root|
      snapshot = File.join(root, 'snapshot.json')
      File.write(snapshot, JSON.generate(q: {}, h: {}, visits: {}, returns: [], n_updates: 0, td_abs_sum: 0.0))
      expect(PWN::Config).not_to receive(:refresh_env)
      expect(PWN::AI::Agent::Loop).not_to receive(:run)
      out = StringIO.new
      expect(PWN::AI::CLI.run(argv: ['--policy', 'evaluate', '--baseline', snapshot, '--candidate', snapshot], output: out)).to eq(0)
      reports = JSON.parse(out.string)
      expect(reports.map { |report| report['seed'] }).to eq([0, 1])
      expect(reports).to all(include('protocol' => 'pwn-policy-heldout-v2'))
      stdout, stderr, status = Open3.capture3(
        { 'HOME' => root, 'LANG' => 'C.UTF-8' }, RbConfig.ruby, '-Ilib', 'bin/pwn-ai',
        '--policy', 'evaluate', '--baseline', snapshot, '--candidate', snapshot,
        unsetenv_others: true
      )
      expect(status.success?).to be(true), stderr
      expect(JSON.parse(stdout).map { |report| report['seed'] }).to eq([0, 1])
      expect(Dir.children(root)).to eq(['snapshot.json'])
    end
  end

  it 'promotes only with both operator acknowledgements and rolls back using the saved receipt' do
    Dir.mktmpdir('pwn-cli-policy-', '/tmp') do |root|
      output, error, status = Open3.capture3(
        { 'HOME' => root, 'LANG' => 'C.UTF-8' }, RbConfig.ruby,
        File.expand_path('../../../../scripts/benchmark_policy.rb', __dir__),
        '--heldout', '--snapshot-dir', File.join(root, 'snapshots'), unsetenv_others: true
      )
      expect(status.success?).to be(true), error
      baseline = File.join(root, 'snapshots', 'off.json')
      candidate = File.join(root, 'snapshots', 'on.json')
      reports = File.join(root, 'reports.json')
      File.write(reports, JSON.generate(JSON.parse(output).fetch('heldout')))
      live = File.join(root, 'live.json')
      FileUtils.cp(baseline, live)
      argv = ['--policy', 'promote', '--baseline', baseline, '--candidate', candidate, '--reports', reports, '--live-policy', live]
      expect(PWN::Config).not_to receive(:refresh_env)
      expect(PWN::AI::Agent::Loop).not_to receive(:run)
      [[], ['--approve-policy-change'], ['--policy-writers-stopped']].each do |flags|
        expect(PWN::AI::CLI.run(argv: argv + flags, output: StringIO.new)).to eq(1)
        expect(File.binread(live)).to eq(File.binread(baseline))
      end
      approval = %w[--approve-policy-change --policy-writers-stopped]
      original_reports = File.read(reports)
      tampered = JSON.parse(original_reports)
      tampered.first['passed'] = true
      File.write(reports, JSON.generate(tampered))
      rejected = StringIO.new
      expect(PWN::AI::CLI.run(argv: argv + approval, output: rejected)).to eq(1)
      expect(JSON.parse(rejected.string)).to include('promoted' => false, 'reason' => 'provenance/artifact replay mismatch')
      expect(File.binread(live)).to eq(File.binread(baseline))
      File.write(reports, original_reports)
      out = StringIO.new
      expect(PWN::AI::CLI.run(argv: argv + approval, output: out)).to eq(0)
      expect(JSON.parse(out.string)).to include('promoted' => true, 'replayed_seeds' => [0, 1])
      expect(File.binread(live)).to eq(File.binread(candidate))
      receipt = File.join(root, 'receipt.json')
      File.write(receipt, out.string)
      rollback = ['--policy', 'rollback', '--receipt', receipt, '--live-policy', live]
      expect(PWN::AI::CLI.run(argv: rollback, output: StringIO.new)).to eq(1)
      expect(File.binread(live)).to eq(File.binread(candidate))
      File.write(live, File.read(baseline))
      expect(PWN::AI::CLI.run(argv: rollback + approval, output: StringIO.new)).to eq(1)
      File.write(live, File.read(candidate))
      expect(PWN::AI::CLI.run(argv: rollback + approval, output: StringIO.new)).to eq(0)
      expect(File.binread(live)).to eq(File.binread(baseline))
    end
  end

  it 'rejects policy flags outside their action and never combines offline evaluation with a live session' do
    [
      %w[--baseline baseline.json],
      %w[--approve-policy-change],
      %w[--policy evaluate --baseline b --candidate c --ai prompt],
      %w[--policy evaluate --baseline b --candidate c --replay session],
      %w[--policy evaluate --baseline b --candidate c --mission mission],
      %w[--policy evaluate --baseline b --candidate c --pwn-env vault],
      %w[--policy evaluate --baseline b --candidate c --live-policy live],
      %w[--policy evaluate --baseline b --candidate c --approve-policy-change],
      %w[--policy evaluate --baseline b],
      %w[--policy rollback --receipt r],
      %w[--policy promote --baseline b --candidate c --reports r],
      %w[--policy rollback --receipt r --live-policy l --candidate c]
    ].each do |argv|
      expect { PWN::AI::CLI.parse(argv: argv) }.to raise_error(OptionParser::ParseError), argv.inspect
    end
  end

  it 'returns nonzero JSON diagnostics for malformed offline inputs without starting a session' do
    Dir.mktmpdir('pwn-cli-policy-', '/tmp') do |root|
      path = File.join(root, 'invalid.json')
      File.write(path, 'not json')
      expect(PWN::Config).not_to receive(:refresh_env)
      expect(PWN::Sessions).not_to receive(:create)
      expect(PWN::AI::Agent::Loop).not_to receive(:run)
      [
        ['--policy', 'evaluate', '--baseline', path, '--candidate', path],
        ['--policy', 'rollback', '--receipt', path, '--live-policy', path, '--approve-policy-change', '--policy-writers-stopped']
      ].each do |argv|
        out = StringIO.new
        expect(PWN::AI::CLI.run(argv: argv, output: out)).to eq(1)
        expect(JSON.parse(out.string)).to have_key('error')
        expect(File.read(path)).to eq('not json')
      end
    end
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
    home = Dir.mktmpdir('pwn-cli-plan-')
    stub_const('PWN::AI::Agent::Mission::ROOT', File.join(home, 'missions'))
    stub_const('PWN::AI::Agent::OpenGoal::GOAL_FILE', File.join(home, 'open_goal.json'))
    expect(PWN::AI::Agent::Loop).not_to receive(:run)
    expect(PWN::AI::Agent::Dispatch).not_to receive(:call)
    out = StringIO.new
    expect(PWN::AI::CLI.run(argv: ['--plan-only', '--ai', 'echo one then echo two'], output: out)).to eq(0)
    dag = YAML.safe_load(out.string)
    expect(dag['steps'].length).to be >= 2
    expect(dag['steps'].first).to include('tool', 'args', 'side_effect', 'dependencies')
  ensure
    FileUtils.remove_entry(home) if home && Dir.exist?(home)
  end

  it 'writes a mission ledger for --plan-only and binds it on --execute' do
    home = Dir.mktmpdir('pwn-cli-mission-')
    allow(PWN::Config).to receive(:refresh_env)
    stub_const('PWN::AI::Agent::Mission::ROOT', File.join(home, 'missions'))
    stub_const('PWN::AI::Agent::OpenGoal::GOAL_FILE', File.join(home, 'open_goal.json'))
    stub_const('PWN::AI::Agent::TaskDAG::ROOT', File.join(home, 'runs'))
    out = StringIO.new
    expect(PWN::AI::CLI.run(argv: ['--plan-only', '--ai', 'echo one then echo two', '--mission', 'lab'], output: out)).to eq(0)
    expect(PWN::AI::Agent::Mission.current(id: 'lab')[:request]).to eq('echo one then echo two')
    expect(PWN::AI::Agent::OpenGoal.current[:mission_id]).to eq('lab')
    dag_path = File.join(home, 'missions', 'lab', 'dag.yaml')
    File.write(dag_path, File.read(dag_path).sub("tool: shell\n", "tool: shell\n    hand_written: true\n"))
    expect(PWN::AI::Agent::TaskDAG).to receive(:execute).and_return(run_id: 'lab-run', ok: true, results: [])
    expect(PWN::AI::CLI.run(argv: ['--execute', dag_path, '--mission', 'lab'], output: StringIO.new)).to eq(0)
    expect(PWN::AI::Agent::Mission.current(id: 'lab')[:run_id]).to eq('lab-run')
  ensure
    FileUtils.remove_entry(home) if home && Dir.exist?(home)
  end

  it 'rejects an inferred shell step on operator execute' do
    home = Dir.mktmpdir('pwn-cli-shell-')
    allow(PWN::Config).to receive(:refresh_env)
    stub_const('PWN::AI::Agent::Mission::ROOT', File.join(home, 'missions'))
    path = File.join(home, 'dag.yaml')
    File.write(path, YAML.dump('steps' => [{ 'id' => 's1', 'tool' => 'shell', 'args' => { 'command' => 'true' }, 'dependencies' => [] }]))
    expect(PWN::AI::CLI.run(argv: ['--execute', path, '--mission', 'lab'], output: StringIO.new)).to eq(1)
  ensure
    FileUtils.remove_entry(home) if home && Dir.exist?(home)
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
