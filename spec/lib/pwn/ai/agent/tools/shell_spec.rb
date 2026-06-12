# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools shell' do
  it 'registers the shell tool' do
    PWN::AI::Agent::Registry.discover
    expect(PWN::AI::Agent::Registry.lookup(name: 'shell')).not_to be_nil
  end
end
