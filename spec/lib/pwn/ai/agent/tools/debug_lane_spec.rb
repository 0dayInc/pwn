# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools debug_lane' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/debug_lane.rb'
  end

  it 'registers debug_session binary_diff crash_triage emulate detonate budget_status pty_expect' do
    %w[debug_session binary_diff crash_triage capability_request emulate detonate budget_status pty_expect].each do |name|
      expect(PWN::AI::Agent::Registry.lookup(name: name)).not_to be_nil
    end
  end
end
