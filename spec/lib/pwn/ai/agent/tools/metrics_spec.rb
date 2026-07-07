# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools metrics' do
  it 'registers the metrics_summary tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'metrics_summary')).not_to be_nil
  end

  it 'registers the metrics_reset tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'metrics_reset')).not_to be_nil
  end

  it 'exposes the metrics toolset in the registry' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.toolsets).to include('metrics')
  end
end
