# frozen_string_literal: true

require 'spec_helper'

describe 'ROP normalized adapter' do
  it 'enumerates actual ELF gadgets and applies constraints without execution' do
    require 'pwn/plugins/rop'
    expect(PWN::Plugins.const_defined?(:ROP)).to eq(true)
    result = PWN::Plugins::ROP.gadgets(path: '/bin/true', constraints: { contains: 'ret', max_instructions: 2 })
    expect(result[:gadgets]).not_to be_empty
    expect(result[:gadgets]).to all(include(:gadget, :address, :regs_clobbered))
    expect(result[:gadgets].all? { |row| row[:gadget].split(';').length <= 2 }).to eq(true)
  end

  it 'parses ropper and rp listings into queryable gadget records' do
    ropper = <<~TXT
      [INFO] Load gadgets from cache
      0x000000000040101a: pop rdi; ret
      0x000000000040101b: pop rsi; pop r15; ret
    TXT
    rp = <<~TXT
      0x0000000000401020: pop rdx ; ret
      0x401021: ret
    TXT
    a = PWN::Plugins::ROP.parse(text: ropper, backend: 'ropper')
    b = PWN::Plugins::ROP.parse(text: rp, backend: 'rp')
    expect(a.map { |row| row[:gadget] }).to include('pop rdi; ret')
    expect(a.first).to include(:address, :gadget)
    expect(b.map { |row| format('%#x', row[:address]) }).to include('0x401020')
    hits = PWN::Plugins::ROP.filter(gadgets: a + b, constraints: { contains: 'pop rdx' })
    expect(hits.length).to eq(1)
  end
end
