# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools memory' do
  it 'registers the memory_remember tool' do
    PWN::AI::Agent::Registry.discover
    expect(PWN::AI::Agent::Registry.lookup(name: 'memory_remember')).not_to be_nil
  end
end
