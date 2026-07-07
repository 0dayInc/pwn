# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools swarm' do
  before(:all) { PWN::AI::Agent::Registry.discover(force: true) }

  %w[agent_list agent_spawn agent_ask agent_debate agent_broadcast swarm_bus swarm_list].each do |tool|
    it "registers the #{tool} tool" do
      expect(PWN::AI::Agent::Registry.lookup(name: tool)).not_to be_nil
    end
  end

  it 'exposes the swarm toolset in the registry' do
    expect(PWN::AI::Agent::Registry.toolsets).to include('swarm')
  end
end
