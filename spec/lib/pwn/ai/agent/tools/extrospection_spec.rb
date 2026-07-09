# frozen_string_literal: true

require 'spec_helper'
require 'pwn/ai/agent/tools/extrospection'

describe 'PWN::AI::Agent::Tools::Extrospection' do
  it 'registers the extro_snapshot tool' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'extro_snapshot')).not_to be_nil
  end

  it 'registers the extro_observe tool' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'extro_observe')).not_to be_nil
  end

  it 'registers the extro_rf_tune tool' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'extro_rf_tune')).not_to be_nil
  end

  it 'registers the six new limb tools' do
    %w[extro_osint extro_serial extro_telecomm extro_packet extro_vision extro_voice].each do |name|
      expect(PWN::AI::Agent::Registry.lookup(name: name)).not_to be_nil
    end
  end
end
