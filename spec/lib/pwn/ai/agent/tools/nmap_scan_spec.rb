# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'tmpdir'

describe 'PWN::AI::Agent::Tools nmap_scan' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/nmap_scan.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'nmap_scan')).not_to be_nil
  end

  it 'queries yesterday\'s scan diff in one Dispatch call' do
    expect(PWN::Plugins::NmapIt).to receive(:changes).with(hash_including(since: 'yesterday')).and_return(added_ports: [{ port: 80 }])
    raw = PWN::AI::Agent::Dispatch.call(
      tool_call: { function: { name: 'nmap_scan', arguments: JSON.generate(since: 'yesterday', engagement: 'lab') } },
      scope_path: File.join(Dir.tmpdir, 'absent.yaml')
    )
    row = JSON.parse(raw, symbolize_names: true).fetch(:result)
    expect(row[:added_ports].first[:port]).to eq(80)
  end
end
