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

  it 'releases decoded instructions and the handle when result conversion fails' do
    allow(described_class).to receive(:available?).and_return(true)
    allocation = FFI::MemoryPointer.new(:char)
    handle = nil
    allow(described_class).to receive(:cs_open) do |_arch, _mode, result|
      handle = result
      result.write_ulong(1)
      0
    end
    allow(described_class).to receive(:cs_disasm) do |*_args, result|
      result.write_pointer(allocation)
      1
    end
    allow(described_class).to receive(:cs_version).and_raise(IOError, 'conversion failed')
    expect(described_class).to receive(:cs_free).with(allocation, 1).once
    expect(described_class).to(receive(:cs_close).once { |value| expect(value).to eq(handle) })
    expect { described_class.disassemble(bytes: "\x90".b) }.to raise_error(IOError, 'conversion failed')
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
