# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools decompile' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/decompile.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'decompile')).not_to be_nil
  end
end
