# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools cron' do
  it 'registers the cron_list tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'cron_list')).not_to be_nil
  end

  it 'registers the cron_create tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'cron_create')).not_to be_nil
  end

  it 'registers the cron_run tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'cron_run')).not_to be_nil
  end

  it 'registers the cron_enable tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'cron_enable')).not_to be_nil
  end

  it 'registers the cron_disable tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'cron_disable')).not_to be_nil
  end

  it 'registers the cron_remove tool' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.lookup(name: 'cron_remove')).not_to be_nil
  end

  it 'exposes the cron toolset in the registry' do
    PWN::AI::Agent::Registry.discover(force: true)
    expect(PWN::AI::Agent::Registry.toolsets).to include('cron')
  end
end
