# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools binary_triage' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/binary_triage.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'binary_triage')).not_to be_nil
  end
end
