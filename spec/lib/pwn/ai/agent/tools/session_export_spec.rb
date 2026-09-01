# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools session_export' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/session_export.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'session_export')).not_to be_nil
  end
end
