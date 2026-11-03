# frozen_string_literal: true

require 'spec_helper'
require 'open3'
require 'tmpdir'

RSpec.describe 'PWN::AI::Agent::MissionNamespace compiler-free process ownership' do
  around do |example|
    previous = PWN::AI::Agent::MissionNamespace.force_exec
    PWN::AI::Agent::MissionNamespace.force_exec = true
    example.run
  ensure
    PWN::AI::Agent::MissionNamespace.force_exec = previous
  end

  it 'does not ask newuidmap for a host uid range starting at 0' do
    source = File.read(File.expand_path('../../../../support/mission_namespace.rb', __dir__))
    expect(source).not_to include('--map-users=0:0:65536')
    expect(source).to include('/proc/#{pid}/uid_map')
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

  it 'terminates owned descendants when the controller dies' do
    Dir.mktmpdir('mission-owner-') do |root|
      ready = File.join(root, 'ready')
      late = File.join(root, 'late')
      owner = fork do
        code = "Process.setsid; File.write(ARGV[0], 'ready'); sleep 1; File.write(ARGV[1], 'late')"
        mission = PWN::AI::Agent::MissionNamespace.new(descriptor: { operation: :command, argv: [RbConfig.ruby, '-e', code, ready, late] })
        sleep 30
      ensure
        mission&.close
        exit!
      end
      Timeout.timeout(10) { sleep 0.01 until File.exist?(ready) }
      Process.kill('KILL', owner)
      Process.wait(owner)
      owner = nil
      sleep 1.2
      expect(File.exist?(late)).to be(false)
    ensure
      if owner
        Process.kill('KILL', owner)
        Process.wait(owner)
      end
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
