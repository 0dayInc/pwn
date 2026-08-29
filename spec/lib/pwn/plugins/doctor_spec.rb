# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::Doctor do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'bin? is false for a missing binary' do
    expect(described_class.bin?(name: 'pwn-no-such-binary-xyz')).to be false
  end

  it 'check returns plugin status rows' do
    rows = described_class.check
    expect(rows).to be_an(Array)
    expect(rows.first).to include(:plugin, :status)
  end
end
