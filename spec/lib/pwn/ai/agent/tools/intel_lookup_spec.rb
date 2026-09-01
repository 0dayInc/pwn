# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools intel_lookup' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/intel_lookup.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'intel_lookup')).not_to be_nil
  end
end
