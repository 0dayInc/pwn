# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools extrospection' do
  it 'registers the extro_snapshot tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'extro_snapshot')).not_to be_nil
  end

  it 'registers the extro_drift tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'extro_drift')).not_to be_nil
  end

  it 'registers the extro_observe tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'extro_observe')).not_to be_nil
  end

  it 'registers the extro_observations tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'extro_observations')).not_to be_nil
  end

  it 'registers the extro_intel tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'extro_intel')).not_to be_nil
  end

  it 'registers the extro_correlate tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'extro_correlate')).not_to be_nil
  end

  it 'exposes the extrospection toolset in the registry' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.toolsets).to include('extrospection')
  end
end
