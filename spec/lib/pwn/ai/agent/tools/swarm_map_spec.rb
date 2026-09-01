# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools swarm_map' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/swarm_map.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'swarm_map')).not_to be_nil
  end
end
