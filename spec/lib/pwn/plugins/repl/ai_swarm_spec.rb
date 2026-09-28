# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::REPL::AISwarm::Controller do
  include_context 'pwn tmp sandbox'

  it 'returns visible errors for malformed commands and synchronous backend failures' do
    controller = described_class.new(session_id: 'fixture')
    expect(controller.execute(line: '/swarm ask scout "unfinished')[:ok]).to be(false)
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
    queued = controller.execute(line: '/swarm ask scout inspect')
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
    controller.execute(line: '/swarm ask scout inspect')
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
    controller.execute(line: '/swarm ask broken inspect')
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
    job = controller.execute(line: '/swarm ask scout inspect')
    entered.pop
    expect(controller.execute(line: '/swarm create other')[:ok]).to be(false)
    expect(controller.execute(line: '/swarm use other')[:ok]).to be(false)
    controller.execute(line: "/swarm cancel #{job[:job_id]}")
    expect(controller.send(:workers).first.join(2)).not_to be_nil
    expect(controller.snapshot[:jobs].first).to include(state: 'cancelled')
    expect(foreign).to be_alive
    controller.close
    expect(controller.execute(line: '/swarm ask scout again')[:ok]).to be(false)
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
    queued = controller.execute(line: '/swarm ask scout inspect the fixture', on_event: ->(type, text) { events << [type, text] })
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
