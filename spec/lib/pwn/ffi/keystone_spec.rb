# frozen_string_literal: true

require 'spec_helper'

describe PWN::FFI::Keystone do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'should respond to available?' do
    expect(described_class).to respond_to :available?
  end

  it 'rejects assemble when libkeystone is unavailable' do
    allow(described_class).to receive(:available?).and_return(false)
    expect { described_class.assemble(asm: 'nop') }.to raise_error(RuntimeError, /libkeystone not available/)
  end

  before(:each, :keystone_integration) do
    expect(described_class.available?).to be(true),
                                          "PWN_TEST_KEYSTONE=1 requires libkeystone. Load error: #{described_class.load_error}"
  end

  it 'assembles nop; ret', :keystone_integration do
    row = described_class.assemble(asm: "nop\nret", arch: 'x86_64')
    expect(row[:engine]).to eq('keystone')
    expect(row[:bytes].bytesize).to be >= 2
  end
end
