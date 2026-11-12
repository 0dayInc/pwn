# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Engagement, 'explicit and IPv6 scope' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    stub_const('PWN::AI::Agent::Engagement::ROOT', File.join(@tmp, 'engagements'))
    stub_const('PWN::AI::Agent::Engagement::ACTIVE_FILE', File.join(described_class::ROOT, 'active'))
  end

  it 'matches IPv6 addresses and bracketed URL hosts without truncating the address' do
    described_class.open(name: 'v6', scope_cidrs: ['2001:db8:1::/48'])
    ['2001:db8:1::42', 'https://[2001:db8:1::42]:8443/report'].each do |target|
      expect(described_class.in_scope?(target: target)).to be(true)
    end
    expect(described_class.in_scope?(ip: '2001:db8:2::42')).to be(false)
  end

  it 'selects the named scope without switching the active engagement' do
    described_class.open(name: 'first', scope_domains: ['first.example'])
    described_class.open(name: 'second', scope_domains: ['second.example'])
    expect(described_class.in_scope?(name: 'first', host: 'first.example')).to be(true)
    expect(described_class.in_scope?(engagement: 'first', host: 'second.example')).to be(false)
    expect(described_class.current_name).to eq('second')
  end

  it 'keeps no active scope optional but rejects an explicitly missing engagement' do
    expect(described_class.in_scope?(host: 'fixture.example')).to be(true)
    expect(described_class.in_scope?(name: 'missing', host: 'fixture.example')).to be(false)
    described_class.open(name: 'deleted', scope_domains: ['fixture.example'])
    File.unlink(File.join(described_class::ROOT, 'deleted.json'))
    expect(described_class.in_scope?(host: 'fixture.example')).to be(false)
  end
end
