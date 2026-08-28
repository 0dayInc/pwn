# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'csv'
require 'tmpdir'

describe 'PWN::Reports format generators' do
  let(:payload) do
    {
      title: 'PWN Format Spec',
      report_name: 'pwn_format_spec',
      executive_summary: 'One finding.',
      findings: [
        {
          id: 'CFG-001',
          title: 'Missing Security Headers',
          severity: 'Low',
          cvss: 4.3,
          description: 'No X-Frame-Options',
          poc: 'GET /',
          recommendation: 'Add headers'
        }
      ]
    }
  end

  {
    PDF: { ext: 'pdf', const: 'PDF' },
    HTML: { ext: 'html', const: 'HTML' },
    Markdown: { ext: 'md', const: 'Markdown' },
    XML: { ext: 'xml', const: 'XML' },
    CSV: { ext: 'csv', const: 'CSV' },
    JSON: { ext: 'json', const: 'JSON' }
  }.each do |label, meta|
    describe "PWN::Reports::#{meta[:const]}" do
      it 'responds to generate, authors, and help' do
        klass = PWN::Reports.const_get(meta[:const])
        expect(klass).to respond_to(:generate)
        expect(klass).to respond_to(:authors)
        expect(klass).to respond_to(:help)
      end

      it "writes a .#{meta[:ext]} report via generate" do
        klass = PWN::Reports.const_get(meta[:const])
        Dir.mktmpdir('pwn_report_fmt') do |dir|
          path = klass.generate(
            dir_path: dir,
            report_name: 'pwn_format_spec',
            results_hash: payload
          )
          expect(path).to eq(File.join(dir, "pwn_format_spec.#{meta[:ext]}"))
          expect(File.file?(path)).to eq(true)
          expect(File.size(path)).to be > 0
          body = File.binread(path)
          case label
          when :PDF
            expect(body.start_with?('%PDF')).to eq(true)
          when :HTML
            expect(body).to match(/<!DOCTYPE html>/i)
            expect(body).to include('Missing Security Headers')
          when :Markdown
            expect(body).to include('# PWN Format Spec')
            expect(body).to include('Missing Security Headers')
          when :XML
            expect(body).to include('<?xml')
            expect(body).to include('Missing Security Headers')
          when :CSV
            rows = CSV.parse(body)
            expect(rows.first).to include('title')
            expect(body).to include('Missing Security Headers')
          when :JSON
            parsed = JSON.parse(body)
            expect(parsed['title']).to eq('PWN Format Spec')
            expect(parsed['findings'].first['id']).to eq('CFG-001')
          end
        end
      end
    end
  end

  it 'honours an explicit path: override' do
    Dir.mktmpdir('pwn_report_path') do |dir|
      out = File.join(dir, 'custom.json')
      path = PWN::Reports::JSON.generate(path: out, results_hash: payload)
      expect(path).to eq(out)
      expect(JSON.parse(File.read(out))['title']).to eq('PWN Format Spec')
    end
  end
end
