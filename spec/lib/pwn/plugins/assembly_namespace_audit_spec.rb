# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::Assembly, 'opcode input regression' do
  before do
    allow(PWN::AI::Agent::Assembly).to receive(:analyze).and_return('offline analysis')
  end

  ['525bc3', '52 5B C3', '52,5B,C3', '\\x52\\x5b\\xc3', %w[52 5B C3], "\x52\x5b\xc3".b].each do |input|
    it "preserves all opcode nibbles for #{input.inspect}" do
      result = described_class.opcodes_to_asm(opcodes: input, arch: 'x86_64', endian: :little)
      expect(result).to include('push rdx', 'pop rbx', 'ret')
    end
  end
end
