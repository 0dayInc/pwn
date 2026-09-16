# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::Debugger do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'recovers a cyclic offset without parsing gdb text' do
    pattern = described_class.cyclic(length: 200)
    slice = pattern[80, 4]
    expect(described_class.cyclic_find(value: slice, length: 200)).to eq(80)
    expect(described_class.to_pwntools_offsets(value: slice, length: 200)[:offset]).to eq(80)
  end

  it 'parses MI register values into a hash' do
    row = described_class.send(:parse_mi, raw: '^done,register-values=[{number="16",name="rip",value="0x41414141"}]')
    expect(row[:ok]).to eq(true)
    expect(row[:registers]['rip']).to eq('0x41414141')
  end
end
