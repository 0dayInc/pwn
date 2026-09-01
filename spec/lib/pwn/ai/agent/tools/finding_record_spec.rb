# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools finding_record' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/finding_record.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'finding_record')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'finding_report')).not_to be_nil
  end
end
