# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL::AISwarm::Controller do
  include_context 'pwn tmp sandbox'

  it 'routes renamed commands and missing arguments through both console entry points' do
    allow(PWN::AI::Agent::Swarm).to receive(:personas).and_return(scout: { role: 'Inspect' })
    allow(PWN::AI::Agent::Swarm).to receive(:create).and_return(swarm_id: 'fixture')
    allow(PWN::AI::Agent::Swarm).to receive(:ask).and_return(reply: 'Direct reply')
    pry = Pry.new
    console = PWN::Plugins::REPL::AIConsole::Console.new(pry: pry, input: StringIO.new, curses: nil, getch: nil)
    controller = described_class.new(session_id: 'fixture')
    console.instance_variable_set(:@swarm, controller)
    pry.config.pwn_ai_swarm = controller
    ['/swarm mission', '/swarm dm', '/swarm dm scout'].each do |line|
      usage = line.include?('mission') ? 'usage: mission REQUEST' : 'usage: dm NAME REQUEST'
      console.submit(line)
      expect(console.instance_variable_get(:@timeline).last[1]).to include(usage)
      expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: line, pry: pry) }.to output(/#{usage}/).to_stdout
    end
    expect(controller.snapshot[:jobs]).to be_empty
    %w[solve roster ask].each do |old|
      expect(controller.execute(line: "/swarm #{old}")[:error]).to eq("unknown /swarm command: #{old}")
    end
    console.submit('/swarm agents')
    expect(console.instance_variable_get(:@timeline).last[1]).to include('scout')
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/swarm agents', pry: pry) }.to output(/scout/).to_stdout
    expect { PWN::Plugins::REPL.pwn_ai_dispatch_slash!(request: '/swarm dm scout inspect', pry: pry) }.to output(/queued/).to_stdout
    controller.send(:workers).each(&:join)
    expect(controller.snapshot[:jobs].last).to include(command: 'dm', result: 'Direct reply')
  ensure
    controller&.close
  end

  it 'rejects a mission without an original request before starting work' do
    controller = described_class.new(session_id: 'fixture')
    expect(PWN::AI::Agent::Swarm).not_to receive(:create)
    expect(controller.execute(line: '/swarm mission')).to include(ok: false, error: 'usage: mission REQUEST')
  ensure
    controller&.close
  end

  it 'returns visible errors for malformed commands and synchronous backend failures' do
    controller = described_class.new(session_id: 'fixture')
    expect(controller.execute(line: '/swarm pause absent')).to include(ok: false, error: 'job not found')
  ensure
    controller&.close
  end

  it 'preserves solve request bytes and exposes real team state and incomplete outcomes' do
    request = "Write  'hello'\nthen verify --literal"
    allow(PWN::AI::Agent::Swarm).to receive(:solve) do |opts|
      expect(opts[:request]).to eq(request)
      expect(opts[:steering]).to be_a(PWN::AI::Agent::Solve::Control)
      opts[:on_state].call(roles: { protagonist: 'build', antagonist: 'done', verifier: 'waiting', integrator: 'waiting' })
      { status: 'incomplete', reply: 'INCOMPLETE: missing check' }
    end
    controller = described_class.new(session_id: 'fixture')
    controller.execute(line: "/swarm mission #{request}")
    controller.send(:workers).each(&:join)
    expect(controller.snapshot[:jobs].first).to include(state: 'incomplete', team: include(roles: include(protagonist: 'build')))
  ensure
    controller&.close
  end

  it 'returns visible errors for malformed commands and synchronous backend failures' do
    controller = described_class.new(session_id: 'fixture')
    expect(controller.execute(line: '/swarm dm scout "unfinished')[:ok]).to be(false)
    allow(PWN::AI::Agent::Swarm).to receive(:create).and_raise(IOError, 'fixture storage unavailable')
    expect(controller.execute(line: '/swarm create fixture')).to include(ok: false, error: 'IOError: fixture storage unavailable')
  ensure
    controller&.close
  end

  it 'exposes roster metadata and retains outcomes without reviving finished jobs' do
    allow(PWN::AI::Agent::Swarm).to receive(:personas).and_return(scout: { role: 'Inspect evidence', engine: 'ollama', model: 'fixture' })
    allow(PWN::AI::Agent::Swarm).to receive(:create).and_return(swarm_id: 'fixture')
    allow(PWN::AI::Agent::Swarm).to receive(:ask).and_return(reply: 'Observed fixture result')
    controller = described_class.new(session_id: 'fixture')
    expect(controller.roster).to include(include(name: 'scout', role: 'Inspect evidence', engine: 'ollama', model: 'fixture'))
    queued = controller.execute(line: '/swarm dm scout inspect')
    controller.send(:workers).each(&:join)
    expect(controller.snapshot[:jobs].first).to include(state: 'completed', result: 'Observed fixture result')
    expect(controller.execute(line: "/swarm steer #{queued[:job_id]} again")[:ok]).to be(false)
    expect(controller.execute(line: "/swarm cancel #{queued[:job_id]}")[:ok]).to be(false)
    expect(controller.busy?).to be(false)
  ensure
    controller&.close
  end

  it 'owns model interrupts on the job thread and copies request-local routing' do
    entered = Queue.new
    allow(PWN::AI::Agent::Swarm).to receive(:create).and_return(swarm_id: 'fixture')
    Thread.current[:pwn_workspace_fixture] = :copied
    allow(PWN::AI::Agent::Swarm).to receive(:ask) do |opts|
      control = opts[:steering]
      entered << [control.instance_variable_get(:@owner), Thread.current, Thread.current[:pwn_workspace_fixture], Thread.current[:pwn_steering_input]]
      { reply: 'done' }
    end
    controller = described_class.new(session_id: 'fixture')
    controller.execute(line: '/swarm dm scout inspect')
    owner, worker, local, marker = entered.pop
    expect(owner).to eq(worker)
    expect(local).to eq(:copied)
    expect(marker).to be_a(PWN::Plugins::REPL::AISwarm::JobControl)
  ensure
    controller&.close
    Thread.current[:pwn_workspace_fixture] = nil
  end

  it 'passes prior speakers to debate, preserves literal flag-like missions, and retains failures' do
    allow(PWN::AI::Agent::Swarm).to receive(:create).and_return(swarm_id: 'fixture')
    calls = []
    allow(PWN::AI::Agent::Swarm).to receive(:ask) do |opts|
      calls << opts
      raise IOError, 'fixture unavailable' if opts[:name] == 'broken'

      { reply: "reply from #{opts[:name]}" }
    end
    controller = described_class.new(session_id: 'fixture')
    controller.execute(line: '/swarm debate scout,critic "--literal mission"')
    controller.send(:workers).each(&:join)
    expect(calls.first[:request]).to eq('--literal mission')
    expect(calls.last[:request]).to include('reply from scout', '--literal mission')
    controller.execute(line: '/swarm dm broken inspect')
    controller.send(:workers).each(&:join)
    expect(controller.snapshot[:jobs].last).to include(state: 'failed', error: 'IOError: fixture unavailable')
  ensure
    controller&.close
  end

  it 'cancels only its owned blocked model and cannot switch swarms while it runs' do
    entered = Queue.new
    foreign = Thread.new { sleep }
    allow(PWN::AI::Agent::Swarm).to receive(:create).and_return(swarm_id: 'fixture')
    allow(PWN::AI::Agent::Swarm).to receive(:ask) do |opts|
      opts[:steering].model(messages: []) do
        entered << true
        Queue.new.pop
      end
      opts[:steering].checkpoint(messages: [])
    end
    controller = described_class.new(session_id: 'fixture')
    job = controller.execute(line: '/swarm dm scout inspect')
    entered.pop
    expect(controller.execute(line: '/swarm create other')[:ok]).to be(false)
    expect(controller.execute(line: '/swarm use other')[:ok]).to be(false)
    controller.execute(line: "/swarm cancel #{job[:job_id]}")
    expect(controller.send(:workers).first.join(2)).not_to be_nil
    expect(controller.snapshot[:jobs].first).to include(state: 'cancelled')
    expect(foreign).to be_alive
    controller.close
    expect(controller.execute(line: '/swarm dm scout again')[:ok]).to be(false)
  ensure
    controller&.close
    foreign&.kill&.join
  end

  it 'runs, steers, and cancels a persona through the existing Swarm API' do
    entered = Queue.new
    allow(PWN::AI::Agent::Swarm).to receive(:ask) do |opts|
      entered << opts[:steering]
      opts[:on_tool].call('shell', { command: 'true' }, '{"success":true}')
      sleep 0.01 until opts[:steering].instance_variable_get(:@stopping)
      raise PWN::Plugins::REPL::AISwarm::JobControl::Stopped, 'cancelled'
    end
    events = Queue.new
    controller = described_class.new(session_id: 'console-session')
    allow(PWN::AI::Agent::Swarm).to receive(:personas).and_return(scout: { role: 'scout' })
    allow(PWN::AI::Agent::Swarm).to receive(:spawn).and_return(name: 'scout')
    controller.execute(line: '/swarm spawn scout inspect evidence')
    queued = controller.execute(line: '/swarm dm scout inspect the fixture', on_event: ->(type, text) { events << [type, text] })
    steering = entered.pop
    expect(queued[:ok]).to eq(true)
    expect(controller.snapshot[:jobs].first[:state]).to eq('running')
    controller.execute(line: "/swarm steer #{queued[:job_id]} stop the scan")
    expect(steering.instance_variable_get(:@pending)).to include('stop the scan')
    controller.execute(line: "/swarm cancel #{queued[:job_id]}")
    sleep 0.05
    expect(controller.snapshot[:jobs].first[:state]).to eq('cancelled')
    expect(events.pop[0]).to eq(:tool)
  ensure
    controller&.close
  end
end
