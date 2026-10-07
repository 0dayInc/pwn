# frozen_string_literal: true

require 'spec_helper'
require 'pry'

RSpec.describe 'Swarm solve' do
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
                 File.write(File.join(@workspace, 'greeting.txt'), @bad ? 'wrong' : 'hello')
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

  it 'executes the real nested Loop with a deterministic provider and host tool' do
    allow(PWN::AI::Agent::Loop).to receive(:run).and_call_original
    allow(PWN::AI::Agent::TaskSummarizer).to receive(:enabled?).and_return(false)
    PWN::Env[:ai][:active] = :openai
    PWN::Env[:ai][:openai] = { key: 'offline-fixture-key' }
    @agent_cfg[:plan_first] = false
    runtime = double('enclosing request route')
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
                  next({ choices: [{ message: { role: 'assistant', content: nil, tool_calls: [{ id: 'write-greeting', type: 'function', function: { name: 'shell', arguments: JSON.generate(command: "printf hello > #{Shellwords.escape(File.join(@workspace, 'greeting.txt'))}", timeout: 5) } }] } }] }) unless File.exist?(File.join(@workspace, 'greeting.txt'))

                  { artifacts: ['greeting.txt'], summary: 'written' }
                when 'critique' then { revision: revision, objections: [] }
                when 'verify' then { revision: revision, checks: [{ requirements: %w[R0 R1], command: 'cat greeting.txt', stdout: 'hello' }] }
                when 'integrate' then { revision: revision, decision: 'accept', summary: 'Verified greeting' }
                end
      { choices: [{ message: { role: 'assistant', content: JSON.generate(content), tool_calls: [] } }] }
    end
    require 'timeout'
    controller = PWN::Plugins::REPL::AISwarm::Controller.new(session_id: 'real-loop-fixture')
    out = Timeout.timeout(15) do
      controller.execute(line: '/swarm mission Write hello to greeting.txt', workspace: @workspace)
      controller.send(:workers).last.value
    end
    expect(out).to include(status: 'accepted')
    expect(out[:evidence].first).to include(stdout: 'hello', exitstatus: 0)
  ensure
    controller&.close
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
    expect(controller.snapshot[:jobs].last[:state]).to eq('paused')
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
