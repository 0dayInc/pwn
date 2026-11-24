# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools memory' do
  it 'does not let a registry call write around the request review' do
    PWN::AI::Agent::Registry.discover
    expect(PWN::Memory).not_to receive(:remember)
    result = PWN::AI::Agent::Registry.lookup(name: 'memory_remember').handler.call(key: 'units', value: 'metric')
    expect(result).to include(success: false, saved: false, execution_state: 'not_started')
  end

  it 'registers the memory_remember tool' do
    PWN::AI::Agent::Registry.discover
    expect(PWN::AI::Agent::Registry.lookup(name: 'memory_remember')).not_to be_nil
  end
end
