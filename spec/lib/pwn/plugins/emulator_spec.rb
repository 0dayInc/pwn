# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::Emulator do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'returns stub plaintext for a decode function' do
    row = described_class.emulate(binary: '/bin/true', addr: '0x401000', backend: 'stub', plaintext: 'secret')
    expect(row[:ret]).to eq('secret')
  end
end
