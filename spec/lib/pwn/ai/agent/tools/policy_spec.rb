# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools policy' do
  before(:all) { PWN::AI::Agent::Registry.discover(force: true) }

  %w[policy_stats policy_evaluate policy_recommend].each do |tool|
    it "registers the #{tool} tool" do
      expect(PWN::AI::Agent::Registry.lookup(name: tool)).not_to be_nil
    end
  end

  it 'exposes policy tools under the policy toolset' do
    tool = PWN::AI::Agent::Registry.lookup(name: 'policy_stats')
    expect(tool.toolset).to eq('policy')
  end
end
