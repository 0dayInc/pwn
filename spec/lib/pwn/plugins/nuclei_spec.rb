# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::Nuclei do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'to_findings maps JSONL rows into report-shaped hashes' do
    rows = [{ 'info' => { 'name' => 'xss', 'severity' => 'high' }, 'matched-at' => 'https://x/' }]
    out = described_class.to_findings(rows: rows)
    expect(out.first).to include(:title, :severity, :url)
  end
end
