# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::Assembly do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::Assembly
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::Assembly
    expect(help_response).to respond_to :help
  end

  it 'assemble and disassemble return structured engine output' do
    asm = described_class.assemble(asm: "nop\nret", arch: 'x86_64')
    expect(asm).to include(:bytes, :hex, :engine)
    expect(asm[:bytes].bytesize).to be >= 2
    expect(%w[keystone metasm]).to include(asm[:engine].to_s)
    dis = described_class.disassemble(bytes: asm[:bytes], arch: 'x86_64')
    expect(dis[:insns]).to be_an(Array)
    blob = dis[:insns].map { |row| "#{row[:mnemonic]} #{row[:op_str]}" }.join(' ')
    expect(blob).to match(/nop/i)
    expect(%w[capstone metasm]).to include(dis[:engine].to_s)
  end

  it 'falls back to metasm when capstone returns a mis-laid-out mnemonic' do
    allow(PWN::FFI).to receive(:available?).and_call_original
    allow(PWN::FFI).to receive(:available?).with(mod: :Capstone).and_return(true)
    allow(PWN::FFI::Capstone).to receive(:disassemble).and_return(
      engine: 'capstone',
      insns: [{ mnemonic: "L\xCB\xEFy", op_str: "L\xCB\xEFy", size: 4 }]
    )
    asm = described_class.assemble(asm: "nop\nret", arch: 'x86_64', engine: 'metasm')
    dis = described_class.disassemble(bytes: asm[:bytes], arch: 'x86_64')
    expect(dis[:engine]).to eq('metasm')
    blob = dis[:insns].map { |row| row[:mnemonic] }.join(' ')
    expect(blob).to match(/nop/i)
  end
end
