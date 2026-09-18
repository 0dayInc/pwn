# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools radare2' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/radare2.rb'
  end

  it 'registers r2_functions and r2_disasm' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'r2_functions')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'r2_disasm')).not_to be_nil
  end
end
