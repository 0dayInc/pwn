# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools workspace_tool' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/workspace_tool.rb'
  end

  it 'registers workspace_tool' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'workspace_tool')).not_to be_nil
  end

  it 'lists the Open WebUI workspace when no name is given' do
    allow(PWN::AI::ServerTools).to receive(:list).with(engine: :openwebui).and_return([{ id: 'ask_jev', name: 'Ask Jev' }])
    result = PWN::AI::Agent::Registry.lookup(name: 'workspace_tool').handler.call({})
    expect(result).to eq([{ id: 'ask_jev', name: 'Ask Jev' }])
  end
end
