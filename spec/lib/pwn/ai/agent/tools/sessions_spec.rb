# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools sessions' do
  it 'registers the sessions_list tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'sessions_list')).not_to be_nil
  end

  it 'registers the sessions_view tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'sessions_view')).not_to be_nil
  end

  it 'registers the sessions_delete tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'sessions_delete')).not_to be_nil
  end

  it 'registers the sessions_stats tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'sessions_stats')).not_to be_nil
  end

  it 'registers the sessions_current tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'sessions_current')).not_to be_nil
  end

  it 'exposes the sessions toolset in the registry' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.toolsets).to include('sessions')
  end
end
