# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::Capstone do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'should respond to available?' do
    expect(described_class).to respond_to :available?
  end

  it 'rejects disassemble when libcapstone is unavailable' do
    allow(described_class).to receive(:available?).and_return(false)
    expect { described_class.disassemble(bytes: "\x90") }.to raise_error(RuntimeError, /libcapstone not available/)
  end

  before(:each, :capstone_integration) do
    expect(described_class.available?).to be(true),
                                          "PWN_TEST_CAPSTONE=1 requires libcapstone. Load error: #{described_class.load_error}"
  end

  it 'disassembles nop', :capstone_integration do
    row = described_class.disassemble(bytes: "\x90\xc3", arch: 'x86_64')
    expect(row[:engine]).to eq('capstone')
    expect(row[:insns].map { |i| i[:mnemonic] }).to include('nop')
  end
end
