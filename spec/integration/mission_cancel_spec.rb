# frozen_string_literal: true

require 'spec_helper'
require 'open3'
require 'tmpdir'
require 'fileutils'
require 'json'

RSpec.describe 'mission cancellation through real subprocesses' do
  def mission_fixture(name, *args)
    Dir.mktmpdir('mission-cancel-') do |root|
      home = File.join(root, 'home')
      work = File.join(root, 'work')
      FileUtils.mkdir_p([home, work])
      fixture = File.expand_path("../support/harness/#{name}.rb", __dir__)
      stdout, stderr, status = Open3.capture3({ 'HOME' => home }, RbConfig.ruby, '-I', File.expand_path('../../lib', __dir__), fixture, work, *args, chdir: work)
      expect(status.success?).to be(true), stderr
      JSON.parse(stdout)
    end
  end

  it 'cancels the legacy interactive entrypoint through a native terminal and accepts its next mission' do
    require 'pty'
    require 'timeout'
    Dir.mktmpdir('mission-legacy-') do |root|
      FileUtils.mkdir_p(File.join(root, 'home'))
      fixture = File.expand_path('../support/harness/mission_legacy.rb', __dir__)
      PTY.spawn({ 'HOME' => File.join(root, 'home') }, RbConfig.ruby, '-I', File.expand_path('../../lib', __dir__), fixture, root, chdir: root) do |reader, writer, pid|
        Timeout.timeout(15) { sleep 0.01 until File.exist?(File.join(root, 'ready')) }
        writer.write("\x03")
        output = +''
        Timeout.timeout(15) do
          loop { output << reader.readpartial(4096) }
        rescue EOFError, Errno::EIO
          nil
        end
        _child, status = Process.wait2(pid)
        expect(status.success?).to be(true), output
        row = output.lines.find { |line| line.start_with?('{') }
        expect(JSON.parse(row)).to include('ready' => true, 'late' => false, 'second' => true, 'tty' => true)
      ensure
        begin
          Process.kill('KILL', pid)
          Process.wait(pid)
        rescue Errno::ESRCH, Errno::ECHILD
          nil
        end
      end
    end
  end

  it 'reaps provider execution before accepting the next console mission' do
    expect(mission_fixture('mission_console')).to include('ready' => true, 'late' => false, 'second' => true, 'fenced' => true)
  end

  it 'hard cancels local command descendants before the next mission' do
    expect(mission_fixture('mission_console', 'command')).to include('ready' => true, 'late' => false, 'second' => true, 'fenced' => true)
  end

  it 'keeps detached tool jobs alive until their enclosing mission exits' do
    expect(mission_fixture('mission_job_lifetime')).to include('survived_tool' => true)
  end

  it 'hard cancels independent swarm provider and tool descendants' do
    expect(mission_fixture('mission_swarm')).to include('ready' => true, 'late' => false)
  end

  it 'fails closed and reaps startup when namespace creation is denied' do
    expect(mission_fixture('mission_unsupported')).to include('blocked' => true, 'actionable' => true, 'reaped' => true)
  end

  it 'owns double-forked jobs on normal exit without killing unrelated processes' do
    expect(mission_fixture('mission_normal_exit')).to include('reaped' => true, 'late' => false, 'unrelated' => true)
  end

  it 'stops and reaps a setsid descendant before cancellation returns' do
    expect(mission_fixture('mission_dispatch')).to include('cancelled' => true, 'descendant_started' => true, 'reaped' => true, 'post_cancel_write' => false)
  end
end
