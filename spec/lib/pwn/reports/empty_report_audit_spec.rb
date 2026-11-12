# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

[PWN::Reports::SAST, PWN::Reports::AIRedTeam].each do |reporter|
  RSpec.describe reporter, 'empty report generation' do
    it 'generates an empty report with the caller supplied name' do
      Dir.mktmpdir('report-empty-audit-') do |dir|
        described_class.generate(dir_path: dir, report_name: 'fixture-empty')
        data = JSON.parse(File.read(File.join(dir, 'fixture-empty.json')))
        expect(data).to eq('report_name' => 'fixture-empty', 'data' => [])
        html = File.read(File.join(dir, 'fixture-empty.html'))
        expect(html).to include('"ajax": "fixture-empty.json"', '</html>')
      end
    end
  end
end
