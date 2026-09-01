# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools fuzz_campaign' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/fuzz_campaign.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'fuzz_campaign')).not_to be_nil
  end
end
