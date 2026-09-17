# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'tmpdir'

describe 'PWN::AI::Agent::Tools loot_query' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/loot_query.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'loot_query')).not_to be_nil
  end

  it 'returns recon creds for lateral-movement planning in one Dispatch call' do
    Dir.mktmpdir('pwn-loot-tool-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      PWN::Plugins::Vault.store(
        secret: 'hunter2',
        username: 'admin',
        host: 'app.example.test',
        service: 'ssh',
        source: 'recon',
        where: 'banner:22',
        finding_id: 'f00bar',
        engagement: 'lab'
      )
      raw = PWN::AI::Agent::Dispatch.call(
        tool_call: {
          function: {
            name: 'loot_query',
            arguments: JSON.generate(host: 'app.example.test', engagement: 'lab')
          }
        },
        scope_path: File.join(dir, 'absent.yaml')
      )
      row = JSON.parse(raw, symbolize_names: true).fetch(:result)
      hit = Array(row[:records] || row).first
      expect(hit[:username]).to eq('admin')
      expect(hit[:finding_id]).to eq('f00bar')
      expect(hit[:host]).to include('app.example.test')
    end
  end
end
