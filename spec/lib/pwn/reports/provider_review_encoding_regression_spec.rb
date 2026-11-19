# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'uri'

[PWN::Reports::SAST, PWN::Reports::AIRedTeam].each do |reporter|
  RSpec.describe reporter, 'PR-SEC-02 inline AJAX encoding' do
    [
      'ordinary',
      'fixture", "review": (globalThis.providerReviewMarker = 1), "unused": "',
      "space &?#%+\\\"'\\\n雪\u2028\u2029",
      'fixture</script><script>providerReviewMarker=1</script>'
    ].each do |name|
      it "preserves the filename as URL data for #{name.inspect}" do
        Dir.mktmpdir('pwn-report-encoding-') do |dir|
          # Slash-containing input also exercises the literal HTML end tag.
          FileUtils.mkdir_p(File.dirname(File.join(dir, "#{name}.html")))
          described_class.generate(dir_path: dir, report_name: name)
          html = File.read(File.join(dir, "#{name}.html"))
          expect(JSON.parse(File.read(File.join(dir, "#{name}.json")))).to eq('report_name' => name, 'data' => [])
          ajax = html.lines.find { |line| line.include?('"ajax":') }.strip.delete_suffix(',')
          url = JSON.parse("{#{ajax}}").fetch('ajax')
          expect(url).not_to match(/[<>"'\\\s&#?]/)
          expect(URI.parse(url).scheme).to be_nil
          expect(URI.decode_www_form_component(url)).to eq("#{name}.json")
          expect(ajax).not_to include('</script>', '<script>', "\u2028", "\u2029")
          scripts = html.scan(%r{<script(?: [^>]*)?>(.*?)</script>}m).flatten.join("\n")
          expect(scripts).not_to include(name) if name.match?(/[<>"']/)
          expect(scripts).not_to include("\u2028", "\u2029")
        end
      end
    end
  end
end
