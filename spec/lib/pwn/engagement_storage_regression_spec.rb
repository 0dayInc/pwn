# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'PWN::Engagement storage boundaries' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    stub_const('PWN::AI::Agent::Engagement::ROOT', File.join(@tmp, 'engagements'))
    stub_const('PWN::AI::Agent::Engagement::ACTIVE_FILE', File.join(@tmp, 'engagements', 'active'))
  end

  it 'rejects traversal names before reading or writing host and scan state' do
    invalid = '../outside'
    [
      -> { PWN::Engagement.record_host(engagement: invalid, host: 'scope.invalid', override: true) },
      -> { PWN::Engagement.hosts(name: invalid) },
      -> { PWN::Engagement.record_scan(engagement: invalid, hosts: []) },
      -> { PWN::Engagement.scans(name: invalid) }
    ].each do |operation|
      expect(&operation).to raise_error(ArgumentError, /Invalid engagement name/)
    end
    expect(File).not_to exist(File.join(@tmp, 'outside'))
  end

  it 'checks the explicit destination scope instead of the unrelated active engagement' do
    PWN::Engagement.open(name: 'destination', scope_domains: ['destination.invalid'])
    PWN::Engagement.open(name: 'current-engagement', scope_domains: ['active.invalid'])
    result = PWN::Engagement.record_host(engagement: 'destination', host: 'destination.invalid', ports: [443])
    expect(result).to include(host: 'destination.invalid', ports: [443])
    expect(PWN::Engagement.hosts(engagement: 'destination')).to have_key(:'destination.invalid')
    expect(PWN::Engagement.hosts(name: 'current-engagement')).to be_empty
  end

  it 'uses the same destination when matching name aliases are supplied' do
    PWN::Engagement.open(name: 'destination', scope_domains: ['destination.invalid'])
    PWN::Engagement.open(name: 'other', scope_domains: ['other.invalid'])
    result = PWN::Engagement.record_host(engagement: 'destination', name: 'destination', host: 'destination.invalid')
    expect(result).to include(host: 'destination.invalid')
    expect(PWN::Engagement.hosts(name: 'destination')).to have_key(:'destination.invalid')
    expect(PWN::Engagement.hosts(name: 'other')).to be_empty
  end
end
