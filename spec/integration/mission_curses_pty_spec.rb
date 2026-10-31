# frozen_string_literal: true

require 'spec_helper'
require 'pty'
require 'io/console'
require 'timeout'

RSpec.describe 'native curses mission cancellation' do
  %w[ordinary command].each do |mode|
    it "handles terminal CTRL+C during #{mode} execution and accepts the next mission without late writes" do
      Dir.mktmpdir('mission-curses-') do |root|
        home = File.join(root, 'home')
        work = File.join(root, 'work')
        FileUtils.mkdir_p([home, work])
        fixture = File.expand_path('../support/harness/mission_curses_pty.rb', __dir__)
        PTY.spawn({ 'HOME' => home, 'TERM' => 'xterm-256color' }, RbConfig.ruby, '-I', File.expand_path('../../lib', __dir__), fixture, work, mode, chdir: work) do |reader, writer, pid|
          writer.winsize = [32, 120]
          output = +''
          pump = Thread.new do
            loop { output << reader.readpartial(4096) }
          rescue EOFError, Errno::EIO
            nil
          end
          %w[idle ready cancelled second].zip([mode == 'command' ? "/mcp fixture\r" : "first\r", "\x03", "second\r", "back\r"]).each do |marker, keys|
            Timeout.timeout(20) { sleep 0.01 until File.exist?(File.join(work, marker)) }
            writer.write(keys)
          end
          Timeout.timeout(20) { pump.join }
          _child, status = Process.wait2(pid)
          expect(status.success?).to be(true), output
          expect(JSON.parse(output[/\{"ready":.*\}/])).to include('ready' => true, 'late' => false, 'second' => true, 'tty' => true)
        ensure
          begin
            Process.kill('KILL', pid)
            Process.wait(pid)
          rescue Errno::ESRCH, Errno::ECHILD
            nil
          end
          pump&.join(1)
        end
      end
    end
  end
end
