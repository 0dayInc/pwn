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
end
