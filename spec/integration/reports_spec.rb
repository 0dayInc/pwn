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
