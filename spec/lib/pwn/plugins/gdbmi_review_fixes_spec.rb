# frozen_string_literal: true

require 'spec_helper'
require 'timeout'

RSpec.describe PWN::Plugins::GDBMI, 'review execution outcome regressions' do
  def with_mi_peer(execution)
    request_r, request_w = IO.pipe
    response_r, response_w = IO.pipe
    commands = []
    peer = Thread.new do
      response_w.write("(gdb)\n")
      while (line = request_r.gets)
        command = line.strip
        commands << command
        break if command == '-gdb-exit'

        response_w.write(command == '-exec-run' ? "#{execution}\n(gdb)\n" : "^done\n(gdb)\n")
      end
    ensure
      response_w.close unless response_w.closed?
      request_r.close unless request_r.closed?
    end
    allow(Open3).to receive(:popen2).and_return([request_w, response_r, peer])
    allow(PWN::Plugins::PreflightChecker).to receive(:bin?).with(name: 'gdb').and_return(true)
    Timeout.timeout(2) { yield commands }
    expect(peer.join(1)).to eq(peer)
    expect(commands.last).to eq('-gdb-exit')
    expect(request_w).to be_closed
    expect(response_r).to be_closed
  ensure
    request_w&.close unless request_w&.closed?
    peer&.join(1)
    peer&.kill&.join if peer&.alive?
    [request_r, response_r, response_w].compact.each { |io| io.close unless io.closed? }
  end

  ['^error,msg="fixture could not execute"', "^running\n^error,msg=\"fixture could not execute\""].each do |execution|
    it "PSR-L05 propagates failed execution including actionable MI details #{execution.inspect}" do
      with_mi_peer(execution) do |commands|
        expect { described_class.run_to_crash(binary: '/fixture/offline') }
          .to raise_error(IOError, /fixture could not execute/)
        expect(commands).not_to include('-data-list-register-values x')
      end
    end
  end

  ['^running', "^running\n*stopped,reason=\"breakpoint-hit\",frame={addr=\"0x1000\"}",
   "^running\n*stopped,reason=\"signal-received\""].each do |execution|
    it "PSR-L05 classifies an unconfirmed outcome as unknown #{execution.inspect}" do
      with_mi_peer(execution) do
        result = described_class.run_to_crash(binary: '/fixture/offline')
        expect(result).to include(signal: nil, exploitability: 'unknown')
      end
    end
  end

  %w[exited-normally exited].each do |reason|
    it "preserves confirmed #{reason} as a no-crash outcome" do
      with_mi_peer("^running\n*stopped,reason=\"#{reason}\"") do
        result = described_class.run_to_crash(binary: '/fixture/offline')
        expect(result).to include(signal: nil, exploitability: 'none', interpreter: 'mi3')
      end
    end
  end

  it 'preserves the crash hash for an actual parsed signal stop' do
    with_mi_peer("^running\n*stopped,reason=\"signal-received\",signal-name=\"SIGABRT\",frame={addr=\"0x1000\"}") do
      result = described_class.run_to_crash(binary: '/fixture/offline')
      expect(result).to include(signal: 'SIGABRT', pc: '0x1000', exploitability: 'abort')
    end
  end
end
