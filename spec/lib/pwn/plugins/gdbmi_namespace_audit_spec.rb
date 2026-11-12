# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::GDBMI, 'stop record regression' do
  it 'does not report a signal when the inferior exits normally' do
    allow(described_class).to receive(:mi).and_return("^done\n*stopped,reason=\"exited-normally\"\n(gdb)\n")
    result = described_class.run_to_crash(session: 'offline')
    expect(result).to include(signal: nil, exploitability: 'none')
  end

  it 'uses the signal and PC from the execution stop instead of inventing SIGSEGV' do
    allow(described_class).to receive(:mi) do |opts|
      case opts[:cmd]
      when '-exec-run'
        "^running\n*stopped,reason=\"signal-received\",signal-name=\"SIGABRT\",frame={addr=\"0x1000\"}\n(gdb)\n"
      when '-data-list-register-values x'
        "^done,register-values=[]\n(gdb)\n"
      when '-stack-list-frames'
        "^done,stack=[frame={level=\"0\",addr=\"0x1000\",func=\"abort\"}]\n(gdb)\n"
      else
        "^error,msg=\"not available\"\n(gdb)\n"
      end
    end
    result = described_class.run_to_crash(session: 'offline')
    expect(result).to include(signal: 'SIGABRT', pc: '0x1000', exploitability: 'abort')
  end
end
