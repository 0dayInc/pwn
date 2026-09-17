# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'tmpdir'

describe 'PWN::AI::Agent::Tools nuclei_scan' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/nuclei_scan.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'nuclei_scan')).not_to be_nil
  end

  it 'records a web finding from JSONL in one Dispatch call' do
    Dir.mktmpdir('pwn-nuclei-tool-') do |dir|
      stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
      jsonl = File.join(dir, 'hit.jsonl')
      File.write(jsonl, "#{JSON.generate(
        'template-id' => 'exposed-panel',
        'matched-at' => 'https://app.example.test/admin',
        'info' => { 'name' => 'Exposed admin panel', 'severity' => 'medium' }
      )}\n")
      raw = PWN::AI::Agent::Dispatch.call(
        tool_call: { function: { name: 'nuclei_scan', arguments: JSON.generate(jsonl: jsonl) } },
        scope_path: File.join(dir, 'absent.yaml')
      )
      row = JSON.parse(raw, symbolize_names: true).fetch(:result)
      expect(row[:findings].first[:template_id]).to eq('exposed-panel')
      stored = PWN::Plugins::Findings.report
      expect(stored.first[:matched_at]).to include('/admin')
      expect(stored.first[:severity].to_s).to match(/medium/i)
    end
  end
end
