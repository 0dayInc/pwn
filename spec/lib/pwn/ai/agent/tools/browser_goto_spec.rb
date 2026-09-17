# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'tmpdir'

describe 'PWN::AI::Agent::Tools browser_goto' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/browser_goto.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'browser_goto')).not_to be_nil
  end

  it 'records an auth-bypass finding with pixel and HAR proof in one Dispatch call' do
    Dir.mktmpdir('pwn-tb-tool-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
      stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
      har = JSON.generate(
        'log' => {
          'version' => '1.2',
          'creator' => { 'name' => 'fixture', 'version' => '1' },
          'entries' => [{ 'request' => { 'method' => 'GET', 'url' => 'https://app.example.test/admin' } }]
        }
      )
      raw = PWN::AI::Agent::Dispatch.call(
        tool_call: {
          function: {
            name: 'browser_goto',
            arguments: JSON.generate(
              url: 'https://app.example.test/admin',
              title: 'Auth bypass',
              severity: 'high',
              html: '<html><h1>Dashboard</h1></html>',
              har: har,
              session_id: 'web'
            )
          }
        },
        scope_path: File.join(dir, 'absent.yaml')
      )
      row = JSON.parse(raw, symbolize_names: true).fetch(:result)
      finding = row[:finding]
      expect(finding[:title]).to match(/auth bypass/i)
      arts = Array(finding[:poc_artifacts]) + Array(finding[:evidence_artifacts]).flat_map { |item| [item[:path], item[:stored]] }
      shot = arts.find { |path| File.file?(path.to_s) && File.binread(path).b.start_with?("\x89PNG".b) }
      har_path = arts.find { |path| File.file?(path.to_s) && File.read(path).include?('/admin') }
      expect(shot).not_to be_nil
      expect(har_path).not_to be_nil
      stored = PWN::Plugins::Findings.report
      expect(stored.first[:title]).to match(/auth bypass/i)
    end
  end
end
