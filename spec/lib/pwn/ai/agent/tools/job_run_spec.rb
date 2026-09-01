# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools job_run' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/job_run.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'job_run')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'job_status')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'job_result')).not_to be_nil
  end
end
