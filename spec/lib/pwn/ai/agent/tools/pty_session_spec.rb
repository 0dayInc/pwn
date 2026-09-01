# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools pty_session' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/pty_session.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'pty_open')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'pty_send')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'pty_read')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'pty_close')).not_to be_nil
  end
end
