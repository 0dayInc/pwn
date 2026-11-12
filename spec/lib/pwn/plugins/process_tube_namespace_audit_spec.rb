# frozen_string_literal: true

require 'spec_helper'
require 'socket'

RSpec.describe PWN::Plugins::ProcessTube, 'ANSI expectation regression' do
  it 'consumes the matching raw prefix when matching through ANSI escapes' do
    reader, writer = UNIXSocket.pair
    tube = described_class.register(io: reader)
    writer.write("\e[31mREADY\e[0m\nNEXT\n")
    result = described_class.expect(id: tube[:id], pattern: /READY/, strip_ansi: true, timeout: 1)
    expect(result[:matched]).to eq('READY')
    expect(described_class.recvline(id: tube[:id], timeout: 1)).to eq("\e[0m\n")
    expect(described_class.recvline(id: tube[:id], timeout: 1)).to eq("NEXT\n")
  ensure
    described_class.close(id: tube[:id]) if tube
    writer&.close
  end
end
