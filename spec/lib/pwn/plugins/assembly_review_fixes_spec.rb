# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::Assembly, 'review binary/text discrimination' do
  before do
    allow(PWN::AI::Agent::Assembly).to receive(:analyze).and_return('offline analysis')
  end

  ["\x41\x42".b, 'AB CD'.b, '\\x41\\x42'.b].each do |bytes|
    it "PSR-L04 preserves explicitly binary bytes #{bytes.inspect} without textual decoding" do
      result = described_class.opcodes_to_asm(opcodes: bytes, arch: 'x86', endian: :little)
      expected = Metasm::Shellcode.disassemble(Metasm::Ia32.new(:little), bytes).to_s.squeeze("\n")
      expect(result).to include(expected)
    end
  end

  ['4142', '41 42', '41,42', '\\x41\\x42', %w[41 42], "['41', '42']"].each do |text|
    it "retains the text opcode format #{text.inspect}" do
      result = described_class.opcodes_to_asm(opcodes: text, arch: 'x86', endian: :little)
      expect(result).to include('inc ecx', 'inc edx')
    end
  end

  it 'documents the raw binary and textual override contract' do
    expect { described_class.help }.to output(/binary-tagged input as textual hex.*binary Strings are raw bytes/).to_stdout
  end

  it 'allows the existing textual-input override for binary-tagged text' do
    result = described_class.opcodes_to_asm(opcodes: '4142'.b, opcodes_always_string_obj: true, arch: 'x86', endian: :little)
    expect(result).to include('inc ecx', 'inc edx')
  end
end
