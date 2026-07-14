# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Extrospection (osint/bridges)' do
  it 'should expose BRIDGE_FEEDS for local passive OSINT tools' do
    e = PWN::AI::Agent::Extrospection
    expect(e.const_get(:BRIDGE_FEEDS)).to eq(%i[theharvester spiderfoot amass reconng])
  end

  it 'should surface a bridge config with timeout / sources / modules / passive' do
    bc = PWN::AI::Agent::Extrospection.send(:osint_bridge_config)
    expect(bc).to include(:timeout, :theharvester_sources, :spiderfoot_modules, :amass_passive)
    expect(bc[:timeout]).to be_a(Integer)
  end

  it 'should route each bridge feed through osint_dispatch without raising' do
    e = PWN::AI::Agent::Extrospection
    e.const_get(:BRIDGE_FEEDS).each do |f|
      res = e.send(:osint_dispatch, feed: f, query: 'notadomain', limit: 1, keys: {})
      expect(res).to be_a(Hash)
    end
  end
end
