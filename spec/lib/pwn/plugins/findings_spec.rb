# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::Findings do
  it 'records and reports a finding' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
      row = described_class.record(title: 'xss', severity: 'high', host: '127.0.0.1', poc: '/tmp/poc.rb')
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
      row = described_class.record(title: 'xss', poc_artifacts: [poc], severity: 'high')
      expect(row[:poc_artifacts]).to include(poc)
      out = described_class.render(dir_path: dir, report_name: 'findings')
      expect(File.file?(out[:markdown])).to be true
      expect(File.file?(out[:html])).to be true
      expect(File.file?(out[:json])).to be true
    end
  end
end
