# frozen_string_literal: true

require 'spec_helper'
require 'pry'

RSpec.describe 'Swarm solve' do # rubocop:disable Metrics/BlockLength -- end-to-end role, verifier and worktree lifecycle
  include_context 'pwn tmp sandbox'

  before do
    @workspace = File.join(@tmp, 'work')
    FileUtils.mkdir_p(@workspace)
    allow(PWN::AI::Agent::Swarm).to receive(:build_persona_prompt).and_return('fixture')
    allow(PWN::AI::Agent::Swarm).to receive(:child_inbox).and_return({})
    allow(PWN::AI::Agent::Swarm).to receive(:child_honesty).and_return({})
    allow(PWN::AI::Agent::Swarm).to receive(:bus_append).and_return({})
    @turns = []
    @bad = false
    @reject = false
    @repair = false
    allow(PWN::AI::Agent::Loop).to receive(:run) do |opts|
      handoff = JSON.parse(opts[:system_role_content].split("SOLVE HANDOFF\n").last, symbolize_names: true)
      @turns << [opts, handoff]
      revision = handoff[:revision]
      answer = case handoff[:phase]
               when 'assess' then { requirements: ['The file contains the requested greeting'], risks: ['Wrong bytes'] }
               when 'build'
                 File.write(File.join(handoff[:workspace], 'greeting.txt'), @bad ? 'wrong' : 'hello')
                 { artifacts: ['greeting.txt'], summary: 'candidate' }
               when 'critique' then { revision: revision, objections: @reject ? ['Wrong output'] : [] }
               when 'verify'
                 { revision: revision, checks: [{ requirements: handoff[:requirements].keys, command: 'cat greeting.txt', stdout: 'hello' }] }
               when 'integrate'
                 @bad = false if @repair
                 { revision: revision, decision: handoff[:evidence].all? { |row| row[:passed] } ? 'accept' : 'repair', repair: 'Write hello', summary: 'Greeting delivered' }
               end
      @hook&.call(handoff, answer)
      JSON.generate(answer)
    end
  end

  it 'executes a real worktree mission through the provider fixture, board and typed human apply' do
    allow(Dir).to receive(:home).and_return(@tmp)
    allow(Pry).to receive(:history).and_return(Pry::History.new(file_path: File.join(@tmp, 'history')))
    [%w[init -q], %w[config user.email fixture@example.invalid], %w[config user.name Fixture], %w[commit --allow-empty -qm baseline]].each do |args|
      _, error, status = Open3.capture3('git', '-C', @workspace, *args)
      raise error unless status.success?
    end
    allow(PWN::AI::Agent::Loop).to receive(:run).and_call_original
    allow(PWN::AI::Agent::TaskSummarizer).to receive(:enabled?).and_return(false)
    PWN::Env[:ai][:active] = :openai
    PWN::Env[:ai][:openai] = { key: 'offline-fixture-key' }
    @agent_cfg[:plan_first] = false
    runtime = PWN::AI::Agent::RequestRuntime.new(request: 'Enclosing request', session_id: 'enclosing', artifact_root: @tmp, trace: false)
    expect(runtime).not_to receive(:call)
    Thread.current[:pwn_request_runtime] = runtime
    allow(PWN::AI::OpenAI).to receive(:chat_with_tools) do |opts|
      system = opts[:messages].find { |row| row[:role].to_s == 'system' }[:content]
      handoff = JSON.parse(system.split("SOLVE HANDOFF\n").last, symbolize_names: true)
      phase = handoff[:phase]
      revision = handoff[:revision]
      content = case phase
                when 'assess' then { requirements: ['Greeting bytes'], risks: [] }
                when 'build'
                  isolated = handoff[:workspace]
                  next({ choices: [{ message: { role: 'assistant', content: nil, tool_calls: [{ id: 'write-greeting', type: 'function', function: { name: 'shell', arguments: JSON.generate(command: 'printf hello > greeting.txt', timeout: 5) } }] } }] }) unless File.exist?(File.join(isolated, 'greeting.txt'))

                  { artifacts: ['greeting.txt'], summary: 'written' }
                when 'critique' then { revision: revision, objections: [] }
                when 'verify' then { revision: revision, checks: [{ requirements: %w[R0 R1], command: 'cat greeting.txt', stdout: 'hello' }] }
                when 'integrate' then { revision: revision, decision: 'accept', summary: 'Verified greeting' }
                end
      { choices: [{ message: { role: 'assistant', content: JSON.generate(content), tool_calls: [] } }] }
    end
    require 'timeout'
    controller = PWN::Plugins::REPL::AISwarm::Controller.new(session_id: 'real-loop-fixture')
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    console.instance_variable_set(:@swarm, controller)
    console.instance_variable_set(:@mission_options, { workspace: @workspace, worktree: true, rounds: 1, verification_timeout: 60 })
    out = Timeout.timeout(15) do
      console.submit('/swarm mission Write hello to greeting.txt')
      controller.send(:workers).last.value
    end
    expect(out).to include(status: 'accepted')
    expect(out[:evidence].first).to include(stdout: 'hello', exitstatus: 0)
    expect(File).not_to exist(File.join(@workspace, 'greeting.txt'))
    console.submit('/evidence')
    console.instance_variable_get(:@operator_worker).join(5)
    console.send(:drain)
    console.handle("\r")
    expect(console.send(:operator_content).join).to include('hello', 'accepted', out[:revision])
    console.handle('d')
    console.handle('a')
    "APPLY #{out[:revision]}".chars.each { |key| console.handle(key) }
    console.handle("\r")
    expect(File.read(File.join(@workspace, 'greeting.txt'))).to eq('hello')
    expect(JSON.parse(File.read(out[:record_path])).dig('application', 'status')).to eq('applied')
  ensure
    console&.send(:stop_worker)
    controller&.close
    if out && out[:worktree]
      Open3.capture3('git', '-C', @workspace, 'worktree', 'remove', '--force', out[:worktree][:path])
      FileUtils.remove_entry(out[:worktree][:owner]) if File.directory?(out[:worktree][:owner])
    end
    Thread.current[:pwn_request_runtime] = nil
  end

  it 'runs all roles with the unchanged request and accepts only executed evidence for the artifact revision' do
    request = 'Write the greeting hello to greeting.txt'
    states = []
    out = PWN::AI::Agent::Swarm.solve(
      request: request, workspace: @workspace, on_state: ->(state) { states << state },
      on_tool: ->(*) { expect(states.last[:roles]['verifier']).to eq('checking') }
    )
    expect(out).to include(ok: true, status: 'accepted', request: request)
    expect(@turns.map { |_, handoff| handoff[:phase] }).to eq(%w[assess build critique verify integrate])
    expect(@turns.map { |opts, _| opts[:request] }.uniq).to eq([request])
    expect(out[:evidence].first).to include(passed: true, stdout: 'hello', exitstatus: 0, revision: out[:revision])
    expect(File.read(File.join(@workspace, 'greeting.txt'))).to eq('hello')
    record = JSON.parse(File.read(out[:record_path]))
    expect(record['revision']).to eq(out[:revision])
    expect(record['evidence'].first['stdout']).to eq('hello')
    expect(record['records']).to include(include('phase' => 'candidate', 'revision' => out[:revision], 'artifacts' => out[:artifacts]))
    expect(out[:reply]).to include('R0', 'greeting.txt', out[:revision])
  end

  it 'publishes immutable executed evidence and durable phase checkpoints before completion' do
    states = []
    PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, on_state: lambda { |state|
      expect(File).to exist(state[:record_path])
      disk = JSON.parse(File.read(state[:record_path]), symbolize_names: true)
      expect(disk[:records]).to eq(JSON.parse(JSON.generate(state[:records]), symbolize_names: true))
      states << state
    })
    checked = states.find { |state| state[:evidence]&.any? }
    expect(checked).not_to be_nil
    expect(checked[:evidence].first).to include(stdout: 'hello', passed: true)
    expect(checked[:uncovered]).to eq([])
    expect(states.first[:evidence]).to eq([])
  end

  it 'denies a legacy ordinary request while the canonical workspace is leased' do
    lock_path = File.join(Dir.tmpdir, "pwn-solve-#{Digest::SHA256.hexdigest(File.realpath(@workspace))}.lock")
    File.open(lock_path, File::RDWR | File::CREAT, 0o600) do |lock|
      lock.flock(File::LOCK_EX)
      expect(PWN::AI::Agent::Loop).not_to receive(:run)
      Dir.chdir(@workspace) do
        expect { PWN::Plugins::REPL.pwn_ai_run_steerable(request: 'Keep original', input: StringIO.new, output: StringIO.new) }.to raise_error(/workspace/)
      end
    end
    expect(Thread.current[:pwn_steering_input]).to be_nil
  end

  it 'routes the legacy slash entry to an executed solve, not a normal model request' do
    pry = Pry.new
    controller = nil
    Dir.chdir(@workspace) do
      expect(PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/swarm mission Write hello to greeting.txt', pry: pry)).to be(true)
      controller = pry.config.pwn_ai_swarm
      expect(controller).to be_a(PWN::Plugins::REPL::AISwarm::Controller)
      controller.send(:workers).each(&:join)
      expect(controller.snapshot[:jobs].last[:state]).to eq('accepted')
    end
  ensure
    controller&.close
  end

  it 'binds identical artifact bytes to the specific objective and solve run' do
    first = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace)
    second = PWN::AI::Agent::Swarm.solve(request: 'Write hello and inspect it', workspace: @workspace)
    expect(first[:artifacts]).to eq(second[:artifacts])
    expect(first[:revision]).not_to eq(second[:revision])
  end

  it 'accepts an explicitly selected silent exit-status contract through Dispatch' do
    @hook = lambda do |handoff, answer|
      next unless handoff[:phase] == 'verify'

      answer[:checks] = [{ requirements: %w[R0 R1], command: 'test "$(cat greeting.txt)" = hello', contract: { type: 'exit_status' } }]
    end
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, rounds: 1)
    expect(out).to include(status: 'accepted')
    expect(out[:evidence].first).to include(passed: true, stdout: '', exitstatus: 0, contract: { type: 'exit_status' })
  end

  it 'evaluates JSON fields, RSpec JSON summaries and artifact properties without trusting model assertions' do
    contracts = [
      ['ruby -rjson -e \'print JSON.generate(greeting: File.read("greeting.txt"))\'', { type: 'json_field', path: ['greeting'], equals: 'hello' }, true],
      ['printf \'{"summary":{"example_count":2,"failure_count":0,"pending_count":0}}\'', { type: 'test_results', format: 'rspec_json' }, true],
      ['printf \'{"summary":{"example_count":0,"failure_count":0,"pending_count":0}}\'', { type: 'test_results', format: 'rspec_json' }, false],
      ['printf \'{"summary":{"example_count":2,"failure_count":0,"pending_count":1}}\'', { type: 'test_results', format: 'rspec_json' }, false],
      ['test -f greeting.txt', { type: 'artifact', path: 'greeting.txt', exists: true, sha256: Digest::SHA256.hexdigest('hello'), size: 5 }, true],
      ['test -f greeting.txt', { type: 'artifact', path: 'greeting.txt', size: 4 }, false],
      ['printf broken', { type: 'json_field', path: ['greeting'], equals: 'hello' }, false],
      ['printf hello; exit 1', { type: 'stdout', equals: 'hello' }, false]
    ]
    contracts.each do |command, contract, passed|
      @hook = lambda do |handoff, answer|
        answer[:checks] = [{ requirements: %w[R0 R1], command: command, contract: contract }] if handoff[:phase] == 'verify'
      end
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, rounds: 1)
      expect(out[:evidence].first).to include(passed: passed, contract: contract), out[:reply]
      expect(out[:ok]).to eq(passed)
    end
  end

  it 'runs real RSpec JSON with an explicit dependency manifest' do
    File.write(File.join(@workspace, 'greeting_spec.rb'), 'RSpec.describe("greeting") { it("matches bytes") { expect(File.read("greeting.txt")).to eq("hello") } }')
    @hook = lambda do |handoff, answer|
      answer[:dependencies] = ['greeting_spec.rb'] if handoff[:phase] == 'build'
      answer[:checks] = [{ requirements: %w[R0 R1], command: 'ruby -S rspec greeting_spec.rb --format json', contract: { type: 'test_results', format: 'rspec_json' } }] if handoff[:phase] == 'verify'
    end
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, rounds: 1)
    expect(out[:status]).to eq('accepted'), out[:reply]
    expect(JSON.parse(out[:evidence].first[:stdout]).dig('summary', 'example_count')).to eq(1)
  end

  it 'retains completed check evidence when the next boundary is cancelled' do
    control = PWN::AI::Agent::Solve::Control.new(input: StringIO.new, output: StringIO.new)
    @hook = lambda do |handoff, answer|
      answer[:checks] *= 2 if handoff[:phase] == 'verify'
    end
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, steering: control, on_tool: ->(*) { control.stop })
    expect(out).to include(status: 'cancelled')
    expect(out[:evidence].length).to eq(1)
    expect(out[:evidence].first).to include(passed: true, stdout: 'hello')
    expect(JSON.parse(File.read(out[:record_path]))['evidence'].length).to eq(1)
  end

  it 'copies declared dependencies and invalidates their changes even beyond the review preview' do
    File.write(File.join(@workspace, 'dependency.txt'), 'x' * 140_000)
    @hook = lambda do |handoff, answer|
      answer[:dependencies] = ['dependency.txt'] if handoff[:phase] == 'build'
      answer[:checks] = [{ requirements: %w[R0 R1], command: 'test "$(wc -c < dependency.txt)" -eq 140000', contract: { type: 'exit_status' } }] if handoff[:phase] == 'verify'
      File.write(File.join(@workspace, 'dependency.txt'), 'changed') if handoff[:phase] == 'integrate'
    end
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, rounds: 1)
    expect(out[:evidence].first).to include(passed: true)
    expect(out).to include(status: 'incomplete', dependencies: include('dependency.txt'))
  end

  it 'bounds verification deadlines and retains executed failed observations' do
    @hook = lambda do |handoff, answer|
      answer[:checks] = [{ requirements: %w[R0 R1], command: 'sleep 3', timeout: 1, contract: { type: 'exit_status' } }] if handoff[:phase] == 'verify'
    end
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, rounds: 1, verification_timeout: 1)
    expect(out).to include(status: 'incomplete')
    expect(out[:evidence].first).to include(passed: false, timeout: 1)
  end

  it 'bounds checks whose descendants hold stdout open after the shell exits' do
    @hook = lambda do |handoff, answer|
      answer[:checks] = [{ requirements: %w[R0 R1], command: 'sleep 4 &', timeout: 1, contract: { type: 'exit_status' } }] if handoff[:phase] == 'verify'
    end
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, rounds: 1, verification_timeout: 1)
    expect(out[:status]).to eq('incomplete')
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 3
  end

  it 'binds executable modes and preserves them in verification copies' do
    File.write(File.join(@workspace, 'verify.sh'), '#!/bin/sh\ntest "$(cat greeting.txt)" = hello'.gsub('\\n', "\n"))
    File.chmod(0o755, File.join(@workspace, 'verify.sh'))
    @hook = lambda do |handoff, answer|
      answer[:dependencies] = ['verify.sh'] if handoff[:phase] == 'build'
      answer[:checks] = [{ requirements: %w[R0 R1], command: './verify.sh', contract: { type: 'exit_status' } }] if handoff[:phase] == 'verify'
      File.chmod(0o644, File.join(@workspace, 'verify.sh')) if handoff[:phase] == 'integrate'
    end
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, rounds: 1)
    expect(out[:evidence].first).to include(passed: true)
    expect(out[:status]).to eq('incomplete')
  end

  it 'bounds role dispatch and preserves the unchanged objective on timeout' do
    @hook = ->(handoff, _answer) { sleep 3 if handoff[:phase] == 'assess' }
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, role_timeout: 1)
    expect(out).to include(status: 'incomplete', request: 'Write hello')
    expect(out[:reply]).to include('deadline')
  end

  context 'isolated Git worktrees' do
    def git(*args)
      stdout, stderr, status = Open3.capture3('git', '-C', @workspace, *args)
      raise stderr unless status.success?

      stdout
    end

    before do
      git('init', '-q')
      git('config', 'user.email', 'fixture@example.invalid')
      git('config', 'user.name', 'Fixture')
      File.write(File.join(@workspace, 'old.txt'), 'remove me')
      git('add', '.')
      git('commit', '-qm', 'fixture base')
    end

    after do
      if @isolated && @isolated != @workspace && File.directory?(@isolated)
        git('worktree', 'remove', '--force', @isolated)
        FileUtils.remove_entry(File.dirname(@isolated))
      end
    end

    it 'executes relative writer tools in the worktree rather than the process checkout' do
      @hook = lambda do |handoff, answer|
        next unless handoff[:phase] == 'build'

        @isolated = handoff[:workspace]
        dispatch = lambda do |command|
          JSON.parse(PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'shell', arguments: JSON.generate(command: command, timeout: 2) } }))
        end
        expect(dispatch.call('pwd').dig('result', 'stdout').strip).to eq(@isolated)
        expect(dispatch.call('printf isolated > only-in-worktree').dig('result', 'exit')).to eq(0)
        answer[:artifacts] << 'only-in-worktree'
      end
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true, rounds: 1)
      expect(out[:status]).to eq('accepted')
      expect(File).not_to exist(File.join(@workspace, 'only-in-worktree'))
      expect(Thread.current[:pwn_solve_workspace]).to be_nil
    end

    it 'reaps a writer command when its role deadline expires' do
      @hook = lambda do |handoff, _answer|
        next unless handoff[:phase] == 'build'

        @isolated = handoff[:workspace]
        PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'shell', arguments: JSON.generate(command: 'sleep 4', timeout: 5) } })
      end
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true, rounds: 1, role_timeout: 1)
      expect(out[:status]).to eq('incomplete')
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 3
      expect(File).not_to exist(File.join(@workspace, 'greeting.txt'))
    end

    it 'requires human confirmation, applies exactly the tested patch, and leaves the source index unchanged' do
      @hook = ->(handoff, _answer) { @isolated = handoff[:workspace] if handoff[:phase] == 'build' }
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true, rounds: 1)
      index = File.binread(File.join(@workspace, '.git/index'))
      args = { record_path: out[:record_path], revision: out[:revision] }
      expect(PWN::AI::Agent::Solve.apply_patch(args)).to include(ok: false)
      expect(File).not_to exist(File.join(@workspace, 'greeting.txt'))
      expect(PWN::AI::Agent::Solve.apply_patch(args.merge(confirmation: "APPLY #{out[:revision]}"))).to include(ok: true, status: 'applied')
      expect(File.read(File.join(@workspace, 'greeting.txt'))).to eq('hello')
      expect(File.binread(File.join(@workspace, '.git/index'))).to eq(index)
      expect(JSON.parse(File.read(out[:record_path]))['application']).to include('status' => 'applied')
    end

    it 'refuses a rewritten report revision without matching revision-bound evidence' do
      @hook = ->(handoff, _answer) { @isolated = handoff[:workspace] if handoff[:phase] == 'build' }
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true, rounds: 1)
      record = JSON.parse(File.read(out[:record_path]))
      record['revision'] = record['worktree']['tested_revision'] = 'forged'
      File.write(out[:record_path], JSON.generate(record))
      applied = PWN::AI::Agent::Solve.apply_patch(record_path: out[:record_path], revision: 'forged', confirmation: 'APPLY forged')
      expect(applied).to include(ok: false, error: /revision/)
      expect(File).not_to exist(File.join(@workspace, 'greeting.txt'))
    end

    it 'rejects skip-worktree hidden modifications instead of dropping an uncommitted base' do
      git('update-index', '--skip-worktree', 'old.txt')
      File.write(File.join(@workspace, 'old.txt'), 'hidden user edit')
      @hook = ->(handoff, _answer) { @isolated = handoff[:workspace] if handoff[:phase] == 'build' }
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true)
      @isolated = out.dig(:worktree, :path)
      expect(out[:reply]).to include('checkout differs from source')
      expect(@turns).to be_empty
      expect(File.read(File.join(@workspace, 'old.txt'))).to eq('hidden user edit')
    end

    it 'refuses unrepresentable permission patches before changing the source' do
      @hook = lambda do |handoff, answer|
        next unless handoff[:phase] == 'build'

        @isolated = handoff[:workspace]
        File.chmod(0o600, File.join(@isolated, 'old.txt'))
        answer[:artifacts] << 'old.txt'
      end
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true, rounds: 1)
      applied = PWN::AI::Agent::Solve.apply_patch(record_path: out[:record_path], revision: out[:revision], confirmation: "APPLY #{out[:revision]}")
      expect(applied[:ok]).to be(false)
      expect(File).not_to exist(File.join(@workspace, 'greeting.txt'))
    end

    it 'rejects apply after original changes, candidate changes, or patch tampering' do
      @hook = ->(handoff, _answer) { @isolated = handoff[:workspace] if handoff[:phase] == 'build' }
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true, rounds: 1)
      args = { record_path: out[:record_path], revision: out[:revision], confirmation: "APPLY #{out[:revision]}" }
      File.write(File.join(@workspace, 'new-user-file'), 'keep')
      expect(PWN::AI::Agent::Solve.apply_patch(args)).to include(ok: false, error: /source changed/)
      File.unlink(File.join(@workspace, 'new-user-file'))
      File.write(File.join(@isolated, 'greeting.txt'), 'changed')
      expect(PWN::AI::Agent::Solve.apply_patch(args)).to include(ok: false, error: /candidate changed/)
      File.write(File.join(@isolated, 'greeting.txt'), 'hello')
      File.write(out[:patch_path], 'tampered')
      expect(PWN::AI::Agent::Solve.apply_patch(args)).to include(ok: false, error: /patch changed/)
      expect(File).not_to exist(File.join(@workspace, 'greeting.txt'))
    end

    it 'preserves failed work for recovery and only explicitly discards its unchanged owned worktree' do
      @bad = true
      @hook = ->(handoff, _answer) { @isolated = handoff[:workspace] if handoff[:phase] == 'build' }
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true, rounds: 1)
      expect(out).to include(status: 'incomplete')
      expect(File).to exist(out[:patch_path])
      expect(File).not_to exist(File.join(@workspace, 'greeting.txt'))
      expect(PWN::AI::Agent::Solve.apply_patch(record_path: out[:record_path], revision: out[:revision], confirmation: "APPLY #{out[:revision]}")).to include(ok: false)
      expect(PWN::AI::Agent::Solve.cleanup_worktree(record_path: out[:record_path])).to include(ok: false)
      expect(PWN::AI::Agent::Solve.cleanup_worktree(record_path: out[:record_path], confirmation: "DISCARD #{out[:revision]}")).to include(ok: true)
      expect(File).not_to exist(@isolated)
      expect(File).to exist(out[:patch_path])
    end

    it 'rejects a changed source index or HEAD even when file contents match' do
      @hook = ->(handoff, _answer) { @isolated = handoff[:workspace] if handoff[:phase] == 'build' }
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true, rounds: 1)
      args = { record_path: out[:record_path], revision: out[:revision], confirmation: "APPLY #{out[:revision]}" }
      index = File.binread(File.join(@workspace, '.git/index'))
      git('update-index', '--chmod=+x', 'old.txt')
      expect(PWN::AI::Agent::Solve.apply_patch(args)).to include(ok: false, error: /source changed/)
      File.binwrite(File.join(@workspace, '.git/index'), index)
      git('commit', '--allow-empty', '-qm', 'advance fixture HEAD')
      expect(PWN::AI::Agent::Solve.apply_patch(args)).to include(ok: false, error: /source changed/)
      expect(File).not_to exist(File.join(@workspace, 'greeting.txt'))
    end

    it 'retains cancelled worktree edits without applying them and refuses cleanup after subsequent user edits' do
      control = PWN::AI::Agent::Solve::Control.new(input: StringIO.new, output: StringIO.new)
      @hook = lambda do |handoff, _answer|
        next unless handoff[:phase] == 'build'

        @isolated = handoff[:workspace]
        control.stop
      end
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true, steering: control)
      expect(out[:status]).to eq('cancelled')
      expect(out[:worktree][:tested_revision]).to be_nil
      expect(File).to exist(out[:patch_path])
      expect(File).not_to exist(File.join(@workspace, 'greeting.txt'))
      File.write(File.join(@isolated, 'user-work.txt'), 'keep me')
      cleaned = PWN::AI::Agent::Solve.cleanup_worktree(record_path: out[:record_path], confirmation: "DISCARD #{out[:revision]}")
      expect(cleaned).to include(ok: false, error: /candidate changed/)
      expect(File.read(File.join(@isolated, 'user-work.txt'))).to eq('keep me')
    end

    it 'rejects dirty original trees rather than silently omitting their uncommitted base' do
      File.write(File.join(@workspace, 'old.txt'), 'user change')
      expect(PWN::AI::Agent::Loop).not_to receive(:run)
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true)
      expect(out[:reply]).to include('clean checkout', 'stash')
      expect(File.read(File.join(@workspace, 'old.txt'))).to eq('user change')
    end

    it 'rejects undeclared changed files instead of hiding them from reviewers' do
      @hook = lambda do |handoff, _answer|
        next unless handoff[:phase] == 'build'

        @isolated = handoff[:workspace]
        File.write(File.join(@isolated, 'hidden.txt'), 'unreviewed')
      end
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true, rounds: 1)
      expect(out).to include(status: 'incomplete')
      expect(out[:reply]).to include('declare all changed files', 'hidden.txt')
    end

    it 'never labels an export failure as accepted' do
      @hook = ->(handoff, _answer) { @isolated = handoff[:workspace] if handoff[:phase] == 'build' }
      allow_any_instance_of(PWN::AI::Agent::Solve::Worktree).to receive(:export).and_raise(IOError, 'disk full')
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true, rounds: 1)
      expect(out).to include(status: 'incomplete', ok: false)
      expect(out[:reply]).to include('disk full')
    end

    it 'creates a detached candidate and a reviewable binary patch including added and deleted files without applying it' do
      original_head = git('rev-parse', 'HEAD')
      index = File.binread(File.join(@workspace, '.git/index'))
      @hook = lambda do |handoff, answer|
        next unless handoff[:phase] == 'build'

        @isolated = handoff[:workspace]
        File.unlink(File.join(@isolated, 'old.txt'))
        answer[:artifacts] << 'old.txt'
        File.binwrite(File.join(@isolated, 'binary.bin'), "\x00\xff".b)
        answer[:artifacts] << 'binary.bin'
      end
      out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, worktree: true, rounds: 1)
      expect(out).to include(status: 'accepted', workspace: @isolated)
      expect(@isolated).not_to eq(@workspace)
      expect(File).not_to exist(File.join(@workspace, 'greeting.txt'))
      expect(File.read(File.join(@workspace, 'old.txt'))).to eq('remove me')
      expect(git('rev-parse', 'HEAD')).to eq(original_head)
      expect(File.binread(File.join(@workspace, '.git/index'))).to eq(index)
      expect(File.read(out[:patch_path])).to include('new file mode', 'deleted file mode', 'GIT binary patch')
      expect(out[:worktree]).to include(base: original_head.strip, tested_revision: out[:revision])
      applied = PWN::AI::Agent::Solve.apply_patch(record_path: out[:record_path], revision: out[:revision], confirmation: "APPLY #{out[:revision]}")
      expect(applied).to include(ok: true)
      expect(File).not_to exist(File.join(@workspace, 'old.txt'))
      expect(File.binread(File.join(@workspace, 'binary.bin'))).to eq("\x00\xff".b)
      expect(File.binread(File.join(@workspace, '.git/index'))).to eq(index)
    end
  end

  it 'rejects failing checks even when integration claims accept' do
    @bad = true
    @hook = ->(handoff, answer) { answer[:decision] = 'accept' if handoff[:phase] == 'integrate' }
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, rounds: 1)
    expect(out).to include(status: 'incomplete', ok: false)
    expect(out[:evidence].first).to include(stdout: 'wrong', exitstatus: 0, passed: false)
  end

  it 'repairs through the sole writer and reruns verification against changed bytes' do
    @bad = @repair = true
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace)
    expect(out[:status]).to eq('accepted')
    builds = @turns.select { |_, row| row[:phase] == 'build' }
    expect(builds.length).to eq(2)
    expect(builds.last.last[:repair]).to include(instruction: 'Write hello')
    verifications = out[:records].select { |row| row[:phase] == 'verification' }
    expect(verifications.map { |row| row[:evidence].first[:passed] }).to eq([false, true])
    expect(out[:records].select { |row| row[:phase] == 'verify' }.map { |row| row[:revision] }.uniq.length).to eq(2)
  end

  it 'does not accept unresolved objections or missing requirement coverage' do
    @reject = true
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, rounds: 1)
    expect(out[:status]).to eq('incomplete')
    expect(out[:objections]).to eq(['Wrong output'])
    @reject = false
    @hook = ->(handoff, answer) { answer[:checks].first[:requirements] = ['R1'] if handoff[:phase] == 'verify' }
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, rounds: 1)
    expect(out).to include(status: 'incomplete', uncovered: ['R0'])
  end

  it 'invalidates evidence if the working artifact changes during integration' do
    @hook = ->(handoff, _answer) { File.write(File.join(@workspace, 'greeting.txt'), 'changed') if handoff[:phase] == 'integrate' }
    expect(PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, rounds: 1)[:status]).to eq('incomplete')
  end

  it 'rejects stale handoffs and copy-modifying verification' do
    @hook = ->(handoff, answer) { answer[:revision] = 'old' if handoff[:phase] == 'critique' }
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace)
    expect(out[:reply]).to include('stale revision')
    @hook = lambda do |handoff, answer|
      answer[:checks].first[:command] = 'printf wrong > greeting.txt; printf hello' if handoff[:phase] == 'verify'
    end
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, rounds: 1)
    expect(out[:status]).to eq('incomplete')
    expect(File.read(File.join(@workspace, 'greeting.txt'))).to eq('hello')
  end

  it 'propagates steering to every later role and invalidates the previous candidate' do
    control = PWN::AI::Agent::Solve::Control.new(input: StringIO.new, output: StringIO.new)
    steered = false
    @hook = lambda do |handoff, _answer|
      if handoff[:phase] == 'integrate' && !steered
        control.submit('Also verify exact bytes')
        steered = true
      end
    end
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, steering: control)
    expect(out[:status]).to eq('accepted')
    expect(@turns.count { |_, row| row[:phase] == 'build' }).to eq(2)
    expect(out[:requirements]).to include('S1' => 'Also verify exact bytes')
    expect(@turns.last(4).all? { |opts, row| opts[:request] == 'Write hello' && row[:guidance] == ['Also verify exact bytes'] }).to be(true)
  end

  it 'cancels at a tool boundary without claiming completion or undoing work' do
    control = PWN::AI::Agent::Solve::Control.new(input: StringIO.new, output: StringIO.new)
    @hook = ->(handoff, _answer) { control.stop if handoff[:phase] == 'build' }
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace, steering: control)
    expect(out[:status]).to eq('cancelled')
    expect(File.read(File.join(@workspace, 'greeting.txt'))).to eq('hello')
    expect(@turns.length).to eq(2)
  end

  it 'refuses unconfigured providers before any role or login runs' do
    PWN::Env[:ai][:active] = :openai
    PWN::Env[:ai][:openai] = {}
    expect(PWN::AI::Agent::Loop).not_to receive(:run)
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace)
    expect(out[:reply]).to include('configure openai credentials')
  end

  it 'enforces read-only reviewers at Dispatch even for invented tool calls' do
    @hook = lambda do |handoff, _answer|
      next unless handoff[:phase] == 'critique'

      raw = PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'shell', arguments: JSON.generate(command: "touch #{Shellwords.escape(File.join(@workspace, 'forbidden'))}") } })
      expect(JSON.parse(raw)['success']).to be(false)
    end
    PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace)
    expect(File).not_to exist(File.join(@workspace, 'forbidden'))
    expect(Thread.current[:pwn_solve_tools]).to be_nil
  end

  it 'routes configured roles without switching defaults or modifying the global registry' do
    PWN::AI::Agent::Swarm.spawn(name: 'solve_antagonist', role: 'Review', engine: :ollama, model: 'Exact/Reviewer:Tag')
    registry = File.binread(PWN::AI::Agent::Swarm::AGENTS_FILE)
    routes = []
    @hook = ->(handoff, _answer) { routes << [handoff[:role], Thread.current[:pwn_swarm_engine], Thread.current[:pwn_swarm_model]] }
    out = PWN::AI::Agent::Swarm.solve(request: 'Write hello', workspace: @workspace)
    expect(out[:status]).to eq('accepted')
    expect(routes.select { |row| row.first == 'antagonist' }).to all(eq(['antagonist', 'ollama', 'Exact/Reviewer:Tag']))
    expect(File.binread(PWN::AI::Agent::Swarm::AGENTS_FILE)).to eq(registry)
    expect(Thread.current[:pwn_swarm_model]).to be_nil
  end

  it 'never opens OAuth or a credential prompt during a solve provider call' do
    Thread.current[:pwn_solve_tools] = []
    { openai: [PWN::AI::OpenAI, :open_ai_rest_call], anthropic: [PWN::AI::Anthropic, :anthropic_rest_call], grok: [PWN::AI::Grok, :grok_rest_call] }.each do |engine, (provider, method)|
      PWN::Env[:ai][engine] = {}
      expect(provider).not_to receive(:obtain_oauth_bearer_token)
      expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
      expect(provider.send(method, rest_call: 'fixture')).to be_nil
    end
  ensure
    Thread.current[:pwn_solve_tools] = nil
  end

  it 'pauses dispatch, resumes, and cancels through the coordinator command entry' do
    entered = Queue.new
    release = Queue.new
    @hook = lambda do |handoff, _answer|
      if handoff[:phase] == 'assess'
        entered << true
        release.pop
      end
    end
    controller = PWN::Plugins::REPL::AISwarm::Controller.new(session_id: 'fixture')
    job = controller.execute(line: '/swarm mission Write hello', workspace: @workspace)
    entered.pop
    expect(controller.execute(line: "/swarm pause #{job[:job_id]}")[:ok]).to be(true)
    release << true
    expect(controller.snapshot[:jobs].last[:state]).to eq('pause_requested')
    expect(controller.execute(line: '/swarm dm other write')[:ok]).to be(false)
    expect(controller.execute(line: "/swarm steer #{job[:job_id]} Check bytes")[:ok]).to be(true)
    expect(controller.execute(line: "/swarm resume #{job[:job_id]}")[:ok]).to be(true)
    controller.execute(line: "/swarm cancel #{job[:job_id]}")
    expect(controller.send(:workers).last.join(3)).not_to be_nil
    expect(controller.snapshot[:jobs].last[:state]).to eq('cancelled')
  ensure
    release << true if release
    controller&.close
  end

  it 'bounds a nonconverging role without inventing a final answer' do
    control = PWN::AI::Agent::Solve::Control.new(input: StringIO.new, output: StringIO.new)
    control.begin_turn
    25.times { control.model(messages: []) { :fixture } }
    expect { control.model(messages: []) { :unreachable } }.to raise_error(PWN::AI::Agent::Solve::Control::Limit)
  end

  it 'runs a draft-preserving Mission with team through the curses confirmation entry' do
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
    controller = PWN::Plugins::REPL::AISwarm::Controller.new(session_id: 'fixture')
    console.instance_variable_set(:@swarm, controller)
    editor = console.instance_variable_get(:@editor)
    editor.place('Write hello to greeting.txt', 4)
    Dir.chdir(@workspace) do
      console.handle("\u0007")
      console.handle('v')
      expect(controller.snapshot[:jobs]).to be_empty
      expect(console.swarm_content.join).to include('mission')
      console.handle("\r")
      controller.send(:workers).each(&:join)
      expect(controller.snapshot[:jobs].last).to include(state: 'accepted', team: include(roles: include('verifier' => 'done')))
      console.handle("\e")
      expect([editor.text, editor.cursor]).to eq(['Write hello to greeting.txt', 4])
    end
  ensure
    controller&.close
  end
end
