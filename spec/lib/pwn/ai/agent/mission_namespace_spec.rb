# frozen_string_literal: true

require 'spec_helper'
require 'open3'
require 'tmpdir'

RSpec.describe PwnSpecNamespaceControllerFixture do
  it 'restores the prior subreaper setting even when a fixture fails' do
    prctl = PWN::AI::Agent::MissionNamespace.native('prctl', [Fiddle::TYPE_INT, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG, Fiddle::TYPE_LONG])
    setting = lambda do
      value = [0].pack('i')
      expect(prctl.call(37, Fiddle::Pointer[value].to_i, 0, 0, 0)).to eq(0)
      value.unpack1('i')
    end
    previous = setting.call
    expect do
      described_class.with_reaping do
        expect(setting.call).to eq(1)
        raise 'synthetic fixture failure'
      end
    end.to raise_error(RuntimeError, 'synthetic fixture failure')
    expect(setting.call).to eq(previous)
  end

  it 'reaps only the adopted controller children after controller death' do
    described_class.with_reaping do
      Dir.mktmpdir('mission-adoption-') do |root|
        ready = File.join(root, 'ready')
        release, sender = IO.pipe
        unrelated = Process.fork do
          sender.close
          release.read(1)
          exit! 41
        end
        allow(PWN::AI::Agent::MissionNamespace).to receive(:new) do
          child = Process.fork do
            sender.close
            release.read(1)
            exit! 0
          end
          File.write("#{ready}.new", child.to_s)
          File.rename("#{ready}.new", ready)
          nil
        end
        owner = described_class.new(descriptor: {})
        release.close
        owner.wait_ready(ready)
        child = Integer(File.read(ready))
        owner.terminate
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        expect { owner.wait_ready(File.join(root, 'never-ready')) }.to raise_error(described_class::StartupError, /class=unavailable.*termsig=9/)
        expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 2
        # The adopted child still holds the diagnostic writer until released.
        sender.write('11')
        sender.close
        owner.close
        expect(owner.status.termsig).to eq(Signal.list.fetch('KILL'))
        expect { Process.waitpid(child, Process::WNOHANG) }.to raise_error(Errno::ECHILD)
        _, unrelated_status = Process.wait2(unrelated)
        expect(unrelated_status.exitstatus).to eq(41)
      ensure
        sender.write('11') if sender && !sender.closed?
        owner&.close
        [release, sender].compact.each { |io| io.close unless io.closed? }
        [child, unrelated].compact.each do |pid|
          Process.waitpid(pid)
        rescue Errno::ECHILD
          nil
        end
      end
    end
  end

  [0, 73].each do |exit_status|
    it "detects owner exit #{exit_status} before readiness even without an IPC report" do
      Dir.mktmpdir('mission-early-exit-') do |root|
        allow(PWN::AI::Agent::MissionNamespace).to receive(:new) { exit! exit_status }
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        owner = described_class.new(descriptor: {})
        pid = owner.pid
        expect { owner.wait_ready(File.join(root, 'never-ready')) }.to raise_error(described_class::StartupError, /class=unavailable.*exitstatus=#{exit_status}/)
        expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 2
        expect(owner.status.exitstatus).to eq(exit_status)
        expect { Process.waitpid(pid, Process::WNOHANG) }.to raise_error(Errno::ECHILD)
      ensure
        owner&.close
      end
    end
  end

  it 'preserves a constructor SystemExit status rather than replacing it in ensure' do
    Dir.mktmpdir('mission-system-exit-') do |root|
      allow(PWN::AI::Agent::MissionNamespace).to receive(:new) { exit 73 }
      owner = described_class.new(descriptor: {})
      expect { owner.wait_ready(File.join(root, 'never-ready')) }.to raise_error(described_class::StartupError, /class=SystemExit.*exitstatus=73/)
    ensure
      owner&.close
    end
  end

  it 'keeps the ten-second payload deadline when the constructor returns without readiness' do
    Dir.mktmpdir('mission-no-marker-') do |root|
      allow(PWN::AI::Agent::MissionNamespace).to receive(:new).and_return(nil)
      expect(Timeout).to receive(:timeout).with(10).and_call_original
      owner = described_class.new(descriptor: {})
      pid = owner.pid
      expect { owner.wait_ready(File.join(root, 'never-ready')) }.to raise_error(Timeout::Error)
      owner.close
      expect(owner.status.termsig).to eq(Signal.list.fetch('KILL'))
      expect { Process.waitpid(pid, Process::WNOHANG) }.to raise_error(Errno::ECHILD)
    ensure
      owner&.close
    end
  end

  it 'closes both diagnostic descriptors and does not signal an already reaped owner' do
    pipes = []
    allow(IO).to receive(:pipe).and_wrap_original do |original|
      original.call.tap { |pair| pipes.concat(pair) }
    end
    allow(PWN::AI::Agent::MissionNamespace).to receive(:new) { exit! 73 }
    owner = described_class.new(descriptor: {})
    expect(pipes.reject(&:closed?)).to all(be_close_on_exec)
    Process.waitpid(owner.pid)
    expect(Process).not_to receive(:kill)
    owner.close
    owner.close
    expect(pipes.length).to eq(2)
    expect(pipes).to all(be_closed)
  ensure
    owner&.close
  end

  [0, -1].each do |invalid_pid|
    it "never signals or waits on an invalid fork PID #{invalid_pid}" do
      pipes = []
      allow(IO).to receive(:pipe).and_wrap_original do |original|
        original.call.tap { |pair| pipes.concat(pair) }
      end
      allow(Process).to receive(:fork).and_return(invalid_pid)
      expect(Process).not_to receive(:kill)
      expect(Process).not_to receive(:wait2)
      expect { described_class.new(descriptor: {}) }.to raise_error(ArgumentError, /positive child PID/)
      expect(pipes.length).to eq(2)
      expect(pipes).to all(be_closed)
    end
  end

  it 'reaps safely when the owner disappears during the child snapshot' do
    allow(PWN::AI::Agent::MissionNamespace).to receive(:new).and_return(nil)
    owner = described_class.new(descriptor: {})
    pid = owner.pid
    allow(File).to receive(:read).and_call_original
    allow(File).to receive(:read).with("/proc/#{pid}/task/#{pid}/children") do
      Process.kill('KILL', pid)
      Process.waitpid(pid)
      raise Errno::ENOENT, 'synthetic concurrent owner reap'
    end
    expect { owner.close }.not_to raise_error
    expect(owner.pid).to be_nil
  ensure
    owner&.close
  end

  it 'closes both diagnostic descriptors if fork fails' do
    pipes = []
    allow(IO).to receive(:pipe).and_wrap_original do |original|
      original.call.tap { |pair| pipes.concat(pair) }
    end
    allow(Process).to receive(:fork).and_raise(Errno::EAGAIN)
    expect(Process).not_to receive(:kill)
    expect { described_class.new(descriptor: {}) }.to raise_error(Errno::EAGAIN)
    expect(pipes).to all(be_closed)
  end

  it 'propagates an early synthetic constructor failure promptly with safe evidence' do
    Dir.mktmpdir('mission-startup-error-') do |root|
      secret = 'synthetic-private-config=DO-NOT-REPORT'
      allow(PWN::AI::Agent::MissionNamespace).to receive(:new) do
        raise PWN::AI::Agent::MissionNamespace::Unavailable, secret
      end
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      owner = described_class.new(descriptor: { operation: :command, argv: ['/bin/true'] })
      pid = owner.pid
      expect { owner.wait_ready(File.join(root, 'never-ready')) }.to raise_error(described_class::StartupError) { |error|
        expect(error.message).to include('PWN::AI::Agent::MissionNamespace::Unavailable', 'exitstatus=1')
        expect(error.message).to match(/location=mission_namespace_spec\.rb:\d+/)
        expect(error.message).not_to include(secret, root, '/opt/pwn', 'argv')
      }
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 2
      expect(owner.status.exitstatus).to eq(1)
      expect { Process.waitpid(pid, Process::WNOHANG) }.to raise_error(Errno::ECHILD)
    ensure
      owner&.close
    end
  end
end

RSpec.describe 'PWN::AI::Agent::MissionNamespace compiler-free process ownership' do
  around do |example|
    previous = PWN::AI::Agent::MissionNamespace.force_exec
    PWN::AI::Agent::MissionNamespace.force_exec = true
    if example.metadata[:controller_fixture]
      PwnSpecNamespaceControllerFixture.with_reaping { example.run }
    else
      example.run
    end
  ensure
    PWN::AI::Agent::MissionNamespace.force_exec = previous
  end

  it 'does not ask newuidmap for a host uid range starting at 0' do
    source = File.read(File.expand_path('../../../../support/mission_namespace.rb', __dir__))
    pid_token = ['#', '{pid}'].join
    expect(source).not_to include('--map-users=0:0:65536')
    expect(source).to include("/proc/#{pid_token}/uid_map")
    expect(source.index('Process.groups = []')).to be < source.index("/proc/#{pid_token}/setgroups")
    expect(source).to include('exit! status')
    expect(source).not_to match(/^\s*exit status\b/)
  end

  it 'loads through root and direct requires without suppressing sibling autoloads' do
    %w[pwn pwn/ai/agent/mission_namespace].each do |entry|
      code = <<~RUBY
        require ARGV.fetch(0)
        owner = PWN::AI::Agent::MissionNamespace
        abort 'wrong owner' unless owner.name == 'PWN::AI::Agent::MissionNamespace'
        abort 'root alias' if PWN.const_defined?(:MissionNamespace, false)
        abort 'missing context' unless PWN::AI::Context.respond_to?(:help)
        abort 'missing runtime' unless PWN::AI::Agent::RequestRuntime.respond_to?(:help)
        puts owner.name
      RUBY
      stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-I', File.expand_path('../../../../../lib', __dir__), '-e', code, entry)
      expect(status.success?).to be(true), stderr
      expect(stdout.strip).to eq('PWN::AI::Agent::MissionNamespace')
    end
  end

  it 'preserves permitted YAML dates, timestamps, symbols and binary strings in snapshots' do
    value = { date: Date.new(2026, 10, 29), time: Time.at(123, 456, :nanosecond).getlocal('+09:00'), bytes: "\xFF".b, route: :openai }
    restored = PWN::AI::Agent::MissionNamespace.decode(PWN::AI::Agent::MissionNamespace.encode(value))
    expect(restored).to eq(value)
    expect(restored[:time].utc_offset).to eq(value[:time].utc_offset)
  end

  it 'preserves the exit status of a failed mission' do
    mission = PWN::AI::Agent::MissionNamespace.new(descriptor: { operation: :command, argv: [RbConfig.ruby, '-e', 'exit! 73'] })
    mission.wait
    expect(mission.status.exitstatus).to eq(73)
  ensure
    mission&.close
  end

  it 'terminates owned descendants when the controller dies', :controller_fixture do
    Dir.mktmpdir('mission-owner-') do |root|
      ready = File.join(root, 'ready')
      late = File.join(root, 'late')
      code = "Process.setsid; File.write(ARGV[0], 'ready'); sleep 1; File.write(ARGV[1], 'late')"
      owner = PwnSpecNamespaceControllerFixture.new(descriptor: { operation: :command, argv: [RbConfig.ruby, '-e', code, ready, late] })
      owner.wait_ready(ready)
      supervisors = File.read("/proc/#{owner.pid}/task/#{owner.pid}/children").split.map { |value| Integer(value, 10) }
      expect(supervisors.length).to eq(1)
      expect(supervisors).to all(be > 1)
      expect(Process).to receive(:kill).with('KILL', owner.pid).once.and_call_original
      owner.terminate
      expect(owner.status.termsig).to eq(Signal.list.fetch('KILL'))
      sleep 1.2
      expect(File.exist?(late)).to be(false)
      owner.close
      supervisors.each { |pid| expect { Process.waitpid(pid, Process::WNOHANG) }.to raise_error(Errno::ECHILD) }
    ensure
      owner&.close
    end
  end

  it 'rejects cyclic snapshots before attempting a launch' do
    value = {}
    value[:self] = value
    expect { PWN::AI::Agent::MissionNamespace.encode(value) }.to raise_error(ArgumentError, /snapshot.*deep/)
  end

  it 'allows cancellation while another thread waits for completion' do
    mission = PWN::AI::Agent::MissionNamespace.new(descriptor: { operation: :command, argv: ['/bin/sleep', '30'] })
    waiter = Thread.new { mission.wait }
    sleep 0.05
    Timeout.timeout(5) do
      mission.close
      waiter.join
    end
    expect(waiter.value).to eq(:reaped)
  ensure
    mission&.close
    waiter&.kill&.join
  end

  it 'enforces the filesystem boundary through a fresh descriptor worker' do
    Dir.mktmpdir('mission-source-') do |root|
      source = File.join(root, 'source')
      work = File.join(root, 'work')
      FileUtils.mkdir_p([source, work])
      File.write(File.join(source, 'keep'), 'original')
      result = PWN::Plugins::AISandbox.protect_call(roots: [source], workspace: work, write_roots: [work],
                                                    handler: { name: 'shell', args: { command: "printf allowed > result; printf bad > #{source}/keep", timeout: 5 } })
      expect(result[:stderr]).to include('Permission denied')
      expect(File.read(File.join(source, 'keep'))).to eq('original')
      expect(File.read(File.join(work, 'result'))).to eq('allowed')
    end
  end

  it 'executes a console slash descriptor after a fresh exec' do
    reader, writer = IO.pipe
    input, sender = IO.pipe
    mission = PWN::AI::Agent::MissionNamespace.new(descriptor: { operation: :slash, request: '/help', generation: 'test', config: {}, baseline_ai: JSON.generate(PWN::Env[:ai]) }, fds: { 4 => writer, 5 => input })
    writer.close
    rows = Timeout.timeout(10) { reader.readlines.map { |line| JSON.parse(line) } }
    mission.wait
    expect(rows.map { |row| row[1] }).to include('command_state')
    expect(rows.none? { |row| row[1] == 'warning' }).to be(true)
  ensure
    mission&.close
    [reader, writer, input, sender].compact.each { |io| io.close unless io.closed? }
  end

  it 'executes a descriptor and reaps detached descendants without an extension' do
    Dir.mktmpdir('mission-ruby-') do |root|
      ready = File.join(root, 'ready')
      late = File.join(root, 'late')
      code = "fork { Process.setsid; File.write(ARGV[0], 'ready'); sleep 1; File.write(ARGV[1], 'late') }; sleep 30"
      mission = PWN::AI::Agent::MissionNamespace.new(descriptor: { operation: :command, argv: [RbConfig.ruby, '-e', code, ready, late] })
      Timeout.timeout(10) { sleep 0.01 until File.exist?(ready) }
      mission.close
      sleep 1.1
      expect(File.exist?(late)).to be(false)
      next_mission = PWN::AI::Agent::MissionNamespace.new(descriptor: { operation: :command, argv: ['/bin/true'] })
      expect(next_mission.wait).to eq(:reaped)
    ensure
      mission&.close
      next_mission&.close
    end
  end
end
