# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'json'

describe PWN::Plugins::Nuclei do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'to_findings maps JSONL rows into report-shaped hashes' do
    rows = [{ 'info' => { 'name' => 'xss', 'severity' => 'high' }, 'matched-at' => 'https://x/', 'template-id' => 'xss-generic' }]
    out = described_class.to_findings(rows: rows)
    expect(out.first).to include(:title, :severity, :url)
    expect(out.first[:template_id] || out.first[:template]).to eq('xss-generic')
  end

  it 'ingests nuclei JSONL into the findings store with matched-at, template id, and severity' do
    Dir.mktmpdir('pwn-nuclei-') do |dir|
      stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
      jsonl = File.join(dir, 'hits.jsonl')
      File.write(jsonl, "#{JSON.generate(
        'template-id' => 'cve-2024-wordpress-rce',
        'matched-at' => 'https://wp.example.test/xmlrpc.php',
        'host' => 'https://wp.example.test',
        'info' => { 'name' => 'WordPress XML-RPC RCE', 'severity' => 'high', 'description' => 'RCE via xmlrpc' }
      )}\n")
      row = described_class.scan(jsonl: jsonl, record: true)
      finding = Array(row[:findings]).first
      expect(finding[:url] || finding[:matched_at]).to include('https://wp.example.test/xmlrpc.php')
      expect(finding[:template_id] || finding[:template]).to eq('cve-2024-wordpress-rce')
      expect(finding[:severity].to_s).to match(/high/i)
      stored = PWN::Plugins::Findings.report
      expect(stored.map { |item| item[:title] }.join).to include('WordPress')
      expect(stored.first[:matched_at] || stored.first[:url]).to include('xmlrpc.php')
      expect(stored.first[:template_id]).to eq('cve-2024-wordpress-rce')
    end
  end

  it 'selects nuclei tags from httpx-detected tech stack' do
    tags = described_class.select_templates(techs: %w[nginx WordPress PHP])
    blob = Array(tags[:tags] || tags).join(',')
    expect(blob).to match(/wordpress/i)
    expect(blob).to match(/nginx/i)
  end
end
