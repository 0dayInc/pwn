# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::PreflightChecker do
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

  it 'selects the first healthy alternative for a proxy task' do
    allow(described_class).to receive(:bin?).and_call_original
    allow(described_class).to receive(:bin?).with(name: 'burpsuite').and_return(false)
    allow(described_class).to receive(:bin?).with(name: 'zaproxy').and_return(true)
    row = described_class.pick(task: 'proxy')
    expect(row[:ok]).to be true
    expect(row[:name]).to eq('zaproxy')
  end

  it 'route degrades missing bins without raising' do
    row = described_class.route(name: 'definitely-not-a-bin-zzzz')
    expect(row[:ok]).to be false
    expect(row[:degraded]).to be true
  end

  it 'check includes missing_services' do
    row = described_class.check.find { |r| r[:plugin].to_s.include?('Packet') }
    expect(row).to include(:missing_services)
  end

  it 'service? is false for a missing unix socket' do
    expect(described_class.service?(name: 'no-such-pwn-svc', path: '/tmp/pwn-no-such.sock')).to be false
  end
end
