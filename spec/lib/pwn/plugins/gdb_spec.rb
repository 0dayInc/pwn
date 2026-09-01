# frozen_string_literal: true

require 'spec_helper'
require 'open3'

describe PWN::Plugins::GDB do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'core raises without a core path' do
    expect { described_class.core(core: '') }.to raise_error(/core is required/)
  end

  it 'breakpoints includes break commands in the gdb batch' do
    allow(Open3).to receive(:capture3).and_return(['ok', '', instance_double(Process::Status, exitstatus: 0)])
    described_class.breakpoints(binary: '/bin/true', breakpoints: ['main', '*0x401000'])
    expect(Open3).to have_received(:capture3) do |*argv|
      joined = argv.flatten.join(' ')
      expect(joined).to include('break main')
      expect(joined).to include('break *0x401000')
    end
  end
end
