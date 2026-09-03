# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::Findings do
  it 'records and reports a finding' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
      row = described_class.record(title: 'xss', severity: 'high', host: '127.0.0.1', poc: '/tmp/poc.rb', evidence: 'PoC at /tmp/poc.rb reproduces XSS in search with a reflected payload.')
      expect(row[:id]).not_to be_empty
      expect(described_class.report.first[:title]).to eq('xss')
    end
  end

  it 'rejects findings without poc artifacts and renders reports with them' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
      expect { described_class.record(title: 'xss') }.to raise_error(/poc/i)
      poc = File.join(dir, 'poc.rb')
      File.write(poc, 'puts 1')
      row = described_class.record(title: 'xss', poc_artifacts: [poc], severity: 'high', evidence: 'PoC file reproduces reflected XSS in search; see artifact path.')
      expect(row[:poc_artifacts]).to include(poc)
      out = described_class.render(dir_path: dir, report_name: 'findings')
      expect(File.file?(out[:markdown])).to be true
      expect(File.file?(out[:html])).to be true
      expect(File.file?(out[:sarif])).to be true
    end
  end

  it 'chains a child finding and reports composite severity' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
      poc = File.join(dir, 'poc.rb')
      File.write(poc, 'puts 1')
      parent = described_class.record(title: 'xss', poc_artifacts: [poc], severity: 'medium', evidence: 'PoC file reproduces reflected XSS in search; see artifact path.')
      child = described_class.chain(parent_id: parent[:id], title: 'account-takeover', poc_artifacts: [poc], severity: 'high')
      expect(child[:chain_parent_id]).to eq(parent[:id])
      expect(child[:composite_severity]).to eq('high')
    end
  end

  it 'flags tampered evidence files' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
      poc = File.join(dir, 'poc.rb')
      File.write(poc, 'puts 1')
      described_class.record(title: 'xss', poc_artifacts: [poc], engagement_id: 'lab', evidence: 'PoC file reproduces reflected XSS in search; see artifact path.')
      expect(described_class.evidence_verify(engagement_id: 'lab')[:ok]).to eq(true)
      File.write(poc, 'tampered')
      expect(described_class.evidence_verify(engagement_id: 'lab')[:ok]).to eq(false)
    end
  end
end
