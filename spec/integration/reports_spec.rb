# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'json'

# ─────────────────────────────────────────────────────────────────────────────
#  #12 — PWN::Reports::* generate valid JSON + HTML from a synthetic
#  findings array. NON-BLOCKING: tmpdir output, no browser, no network.
#  Asserts the CSV/JSON column contract stays stable (downstream
#  DefectDojo importers depend on it).
# ─────────────────────────────────────────────────────────────────────────────

RSpec.describe 'PWN::Reports', :aggregate_failures do
  describe 'directed attack-chain presentation' do
    around do |example|
      Dir.mktmpdir('pwn_chain_evidence') do |dir|
        @evidence_dir = dir
        File.write(File.join(dir, 'proof'), 'demonstrated admin access')
        example.run
      end
    end

    let(:evidence) do
      path = File.join(@evidence_dir, 'proof')
      { label: '<proof>', kind: 'poc', stored: path, sha256: Digest::SHA256.file(path).hexdigest, size: File.size(path) }
    end
    let(:members) do
      [
        { 'id' => 'ssrf', 'title' => 'SSRF <entry>', 'severity' => 'medium', 'cvss' => 5.3, 'enables' => ['admin'] },
        { 'id' => 'admin', 'title' => 'Internal admin', 'severity' => 'medium', 'cvss' => 6.5,
          'chain_assessments' => [{ 'finding_ids' => %w[ssrf admin], 'combined_severity' => 'critical', 'rationale' => 'Verified <admin> access',
                                    'reproduction_steps' => ['Send <request>', 'Observe admin access'], 'evidence_artifacts' => [evidence.transform_keys(&:to_s)] }] },
        { 'id' => 'other', 'title' => 'Other issue', 'severity' => 'high' }
      ]
    end
    let(:chain) do
      payload[:attack_chains].first
    end
    let(:payload) do
      PWN::Reports.package_evidence(payload: PWN::Reports.report_payload(results_hash: { findings: members }), path: File.join(@evidence_dir, 'expected.json'))
    end

    it 'exports one critical chain SARIF result with all constituent metadata and unchanged standalone shape' do
      Dir.mktmpdir('pwn_chain_sarif') do |dir|
        doc = JSON.parse(File.read(PWN::Reports::SARIF.generate(dir_path: dir, report_name: 'chain', results_hash: { findings: members })))
        results = doc['runs'].first['results']
        expect(results.length).to eq(2)
        expect(results.first).to include('level' => 'error', 'message' => { 'text' => chain[:title] })
        expect(results.first['properties']).to include('chain' => JSON.parse(JSON.generate(chain)), 'constituent_findings' => members.first(2))
        attachment = results.first['properties']['chain']['evidence_artifacts'].first.fetch('attachment')
        expect(Digest::SHA256.file(File.join(dir, attachment)).hexdigest).to eq(evidence[:sha256])
        expect(results.last).to eq('ruleId' => 'other', 'level' => 'error', 'message' => { 'text' => 'Other issue' }, 'properties' => members.last)
      end
    end

    it 'exports ranked priorities alongside unchanged constituent findings in JSON' do
      Dir.mktmpdir('pwn_chain_json') do |dir|
        doc = JSON.parse(File.read(PWN::Reports::JSON.generate(dir_path: dir, report_name: 'chain', results_hash: { findings: members })))
        expect(doc['priorities']).to eq(JSON.parse(JSON.generate(payload[:priorities])))
        expect(doc['attack_chains']).to eq(JSON.parse(JSON.generate([chain])))
        expect(doc['findings']).to eq(members)
        attachment = doc['priorities'].first['evidence_artifacts'].first.fetch('attachment')
        expect(Digest::SHA256.file(File.join(dir, attachment)).hexdigest).to eq(evidence[:sha256])
      end
    end

    it 'ranks and documents the critical path before detailed findings in Markdown' do
      Dir.mktmpdir('pwn_chain_md') do |dir|
        text = File.read(PWN::Reports::Markdown.generate(dir_path: dir, report_name: 'chain', results_hash: { findings: members }))
        summary = text.split('## Ranked priorities').last.split('## Attack chains').first
        expect(summary.scan(/^\d+\./).length).to eq(2)
        expect(summary).to include('critical', 'SSRF &lt;entry&gt;')
        expect(summary).not_to include('medium')
        expect(text.index('## Attack chains')).to be < text.index('## Findings')
        expect(text).to include('evidence\\_backed', 'Verified &lt;admin&gt; access', 'Send &lt;request&gt;', 'ssrf \\-&gt; admin', 'attachments/', evidence[:sha256], '5\\.3', '6\\.5')
        expect(text).not_to include('<entry>', '<proof>', '<request>', '<admin>')
      end
    end

    it 'presents one critical path before constituent audit details in HTML' do
      Dir.mktmpdir('pwn_chain_html') do |dir|
        text = File.read(PWN::Reports::HTML.generate(dir_path: dir, report_name: 'chain', results_hash: { findings: members }))
        summary = text.split('<tbody>').last.split('</tbody>').first
        expect(summary.scan('<tr>').length).to eq(2)
        expect(summary).to include('critical', 'SSRF &lt;entry&gt; -&gt; Internal admin')
        expect(summary).not_to include('medium')
        expect(text.index('Attack chains')).to be < text.index('<dt>cvss</dt>')
        expect(text).to include('evidence_backed', 'Verified &lt;admin&gt; access', 'Send &lt;request&gt;', 'ssrf -&gt; admin', 'attachments/', evidence[:sha256], '5.3', '6.5')
        expect(text).not_to include('<entry>', '<proof>', '<request>', '<admin>')
      end
    end
  end

  describe 'standalone SARIF compatibility' do
    it 'preserves distinct metadata for findings without IDs in priority order' do
      Dir.mktmpdir('pwn_sarif_anonymous') do |dir|
        rows = [{ title: 'Lower', severity: 'low', description: 'first' }, { title: 'Higher', severity: 'high', description: 'second' }]
        doc = JSON.parse(File.read(PWN::Reports::SARIF.generate(dir_path: dir, report_name: 'anonymous', results_hash: { findings: rows })))
        results = doc['runs'].first['results']
        expect(results.map { |result| result['properties']['description'] }).to eq(%w[second first])
        expect(results.map { |result| result['level'] }).to eq(%w[error note])
        expect(results.map { |result| result['ruleId'] }).to eq(%w[finding finding])
      end
    end
  end

  describe 'PWN::Reports::SAST.generate' do
    it 'writes <report>.json (valid, contains every finding line_no) and <report>.html' do
      Dir.mktmpdir('pwn_reports_sast') do |dir|
        results = {
          report_name: 'pwn_report_spec',
          data: [
            {
              timestamp: '2026-01-01 00:00:00.000000000 +0000',
              security_references: {
                sast_module: 'PWN::SAST::Eval', section: 'SI-3',
                nist_800_53_uri: 'https://csrc.nist.gov/', cwe_id: '95',
                cwe_uri: 'https://cwe.mitre.org/data/definitions/95.html'
              },
              filename: { git_repo_root_uri: 'https://example.test/repo', entry: 'app.rb' },
              line_no_and_contents: [
                { line_no: '7',  contents: 'eval(x)', author: 'N/A', ai_analysis: 'N/A' },
                { line_no: '19', contents: 'eval(y)', author: 'N/A', ai_analysis: 'N/A' }
              ],
              raw_content: "7:eval(x)\n19:eval(y)\n",
              test_case_filter: 'grep -n eval'
            }
          ]
        }
        PWN::Reports::SAST.generate(dir_path: dir, results_hash: results, report_name: 'pwn_report_spec')

        json_path = File.join(dir, 'pwn_report_spec.json')
        html_path = File.join(dir, 'pwn_report_spec.html')
        expect(File).to exist(json_path)
        expect(File).to exist(html_path)

        parsed = JSON.parse(File.read(json_path))
        expect(parsed['report_name']).to eq('pwn_report_spec')
        expect(parsed['data'].first['line_no_and_contents'].map { |h| h['line_no'] }).to eq(%w[7 19])

        html = File.read(html_path)
        expect(html).to match(/\A\s*<!DOCTYPE HTML>/i)
        expect(html).to include('pwn_report_spec.json')
        expect(html).to include('</html>')
      end
    end
  end

  describe 'PWN::Reports::URIBuster.generate' do
    it 'writes <report>.json and <report>.html for a synthetic results_hash' do
      Dir.mktmpdir('pwn_reports_urib') do |dir|
        results = { report_name: 'pwn_urib_spec', data: [] }
        expect { PWN::Reports::URIBuster.generate(dir_path: dir, results_hash: results) }.not_to raise_error
        expect(File).to exist(File.join(dir, 'pwn_urib_spec.json'))
        expect(JSON.parse(File.read(File.join(dir, 'pwn_urib_spec.json')))).to include('report_name' => 'pwn_urib_spec')
      end
    end
  end

  describe 'PWN::Reports::HTMLHeader.generate' do
    it 'produces a well-formed <head> containing every column name' do
      cols = %w[Timestamp Path Contents]
      html = PWN::Reports::HTMLHeader.generate(column_names: cols, driver_src_uri: 'https://example.test/bin/x')
      expect(html).to match(/\A\s*<!DOCTYPE HTML>/i)
      cols.each { |c| expect(html).to include(c) }
    end
  end
end
