# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools artifacts' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/artifacts.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'artifacts_list')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'artifacts_get')).not_to be_nil
  end
end
