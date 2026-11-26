# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PwnSpecLandlock do
  %w[aarch64-linux aarch64-linux-gnu aarch64_be-linux x86_64-linux].each do |platform|
    it "runs protected-worker examples on #{platform} when the kernel supports ABI 3" do
      stub_const('RUBY_PLATFORM', platform)
      expect(Kernel).to receive(:syscall).with(444, 0, 0, 1).and_return(3)
      expect(described_class.unavailable_reason).to be_nil
    end
  end

  it 'distinguishes an older ABI and an absent syscall from unexpected probe failures' do
    stub_const('RUBY_PLATFORM', 'aarch64-linux')
    allow(Kernel).to receive(:syscall).with(444, 0, 0, 1).and_return(2)
    expect(described_class.unavailable_reason).to include('ABI 3')
    allow(Kernel).to receive(:syscall).with(444, 0, 0, 1).and_raise(Errno::ENOSYS)
    expect(described_class.unavailable_reason).to eq("Errno::ENOSYS: #{Errno::ENOSYS.new.message}")
    allow(Kernel).to receive(:syscall).with(444, 0, 0, 1).and_raise(Errno::EINVAL)
    expect { described_class.unavailable_reason }.to raise_error(Errno::EINVAL)
  end
end
