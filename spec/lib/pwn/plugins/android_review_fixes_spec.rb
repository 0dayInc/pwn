# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'json'
require 'rbconfig'
require 'timeout'

RSpec.describe PWN::Plugins::Android do
  def write_fixture_adb(script)
    # These standalone children need no test bundle; leave the runner's RUBYOPT alone.
    File.write(@adb, "#!#{RbConfig.ruby} --disable=gems,rubyopt\n#{script}")
    File.chmod(0o700, @adb)
  end

  around do |example|
    Dir.mktmpdir('android-review-') do |root|
      @root = root
      @adb = File.join(root, 'adb literal ; executable')
      @calls = File.join(root, 'calls.jsonl')
      write_fixture_adb(<<~RUBY)
        require 'json'
        File.open(#{@calls.inspect}, 'a') { |f| f.puts(JSON.generate(ARGV)) }
        puts 'synthetic'
      RUBY
      example.run
    end
  end

  it 'cancels and reaps only its owned process group, including TERM-resistant descendants' do
    pidfile = File.join(@root, 'pids')
    release = File.join(@root, 'release')
    write_fixture_adb(<<~RUBY)
      child = fork do
        trap('TERM') {}
        File.write(#{"#{pidfile}.ready".inspect}, '')
        sleep 0.01 until File.exist?(#{release.inspect})
      end
      sleep 0.01 until File.exist?(#{"#{pidfile}.ready".inspect})
      File.write(#{"#{pidfile}.tmp".inspect}, [Process.pid, child].join(' '))
      File.rename(#{"#{pidfile}.tmp".inspect}, #{pidfile.inspect})
      sleep 0.01 until File.exist?(#{release.inspect})
      Process.wait(child)
    RUBY
    result = Queue.new
    worker = Thread.new do
      described_class.adb_sh(adb_path: @adb, command: 'synthetic')
    rescue Interrupt => e
      result << e
    end
    Timeout.timeout(5) { Thread.pass until File.exist?(pidfile) }
    owned, descendant = File.read(pidfile).split.map(&:to_i)
    worker.raise(Interrupt, 'synthetic cancellation')
    expect(worker.join(2)).to equal(worker)
    expect(result.pop(timeout: 0.1)).to be_a(Interrupt)
    expect { Process.waitpid(owned, Process::WNOHANG) }.to raise_error(Errno::ECHILD)
    Timeout.timeout(2) do
      loop do
        begin
          break if File.read("/proc/#{descendant}/status").match?(/^State:\s+Z\b/)
        rescue Errno::ENOENT, Errno::ESRCH
          break
        end

        Thread.pass
      end
    end
    expect(Process.kill(0, Process.pid)).to eq(1)
  ensure
    File.write(release, '') if release
    worker&.join(3)
    worker&.kill if worker&.alive?
  end

  it 'surfaces cleanup-only errors inside an unrelated caller rescue' do
    allow(Process).to receive(:kill).and_call_original
    allow(Process).to receive(:kill).with('TERM', kind_of(Integer)).and_raise(IOError, 'cleanup failure')
    begin
      raise 'unrelated caller error'
    rescue RuntimeError
      expect { described_class.adb_sh(adb_path: @adb, command: 'synthetic') }.to raise_error(IOError, 'cleanup failure')
    end
  end

  it 'bounds an owned child that closes stdout but never exits, without exposing its output' do
    write_fixture_adb("STDOUT.close\nsleep 20\n")
    stub_const('PWN::Plugins::Android::COMMAND_TIMEOUT', 1)
    owned = nil
    allow(Process).to receive(:spawn).and_wrap_original do |original, *args, **kwargs|
      owned = original.call(*args, **kwargs)
    end
    expect do
      Timeout.timeout(3) { described_class.adb_sh(adb_path: @adb, command: 'synthetic') }
    end.to raise_error(Timeout::Error, /adb command timed out/)
    expect { Process.waitpid(owned, Process::WNOHANG) }.to raise_error(Errno::ECHILD)
  end

  it 'bounds capture output and suppresses private child stderr on failure' do
    write_fixture_adb("STDERR.puts 'synthetic-private'\nprint 'x' * 2048\n")
    stub_const('PWN::Plugins::Android::MAX_OUTPUT_BYTES', 1024)
    spawn_options = nil
    allow(Process).to receive(:spawn).and_wrap_original do |original, *args, **kwargs|
      spawn_options = kwargs
      original.call(*args, **kwargs)
    end
    expect { described_class.adb_sh(adb_path: @adb, command: 'synthetic') }.to raise_error(IOError, 'adb output limit exceeded')
    expect(spawn_options[:err]).to eq(File::NULL)
  end

  %i[adb_sh adb_push adb_pull take_screenshot screen_record list_installed_apps dumpsys open_app close_app invoke_event_listener].each do |method|
    ['false', 'true', 1, nil].each do |flag|
      it "rejects nonboolean #{flag.inspect} root consent in #{method} before spawning" do
        expect { described_class.public_send(method, adb_path: @adb, as_root: flag) }.to raise_error(ArgumentError, /as_root/)
        expect(File.exist?(@calls)).to be(false)
      end
    end

    [false, true, :omitted].each do |flag|
      it "requires literal true for #{method} with #{flag}" do
        options = { adb_path: @adb, command: 'synthetic', app: 'example.invalid', file: 'a', dest: 'b' }
        options[:as_root] = flag unless flag == :omitted
        described_class.public_send(method, options)
        calls = File.readlines(@calls).map { |line| JSON.parse(line) }
        expect(calls.include?(['root'])).to eq(flag == true)
      end
    end
  end
end
