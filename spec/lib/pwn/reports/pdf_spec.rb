# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'pdf/reader'

describe PWN::Reports::PDF do
  it 'paginates long reports so every finding remains inside the page bounds' do
    Dir.mktmpdir('pdf-page-audit-') do |dir|
      findings = Array.new(80) { |i| { title: "Fixture finding #{i}", description: "Evidence marker #{i}" } }
      path = described_class.generate(path: File.join(dir, 'fixture.pdf'), results_hash: { title: 'Fixture report', findings: findings })
      reader = PDF::Reader.new(path)
      expect(reader.page_count).to be > 1
      text = reader.pages.map(&:text).join("\n")
      findings.each { |row| expect(text).to include(row[:title], row[:description]) }
      reader.pages.each do |page|
        line_count = page.raw_content.scan(') Tj').length
        expect(720 - ((line_count - 1) * 14)).to be >= 72
      end
    end
  end

  it 'preserves literal backslashes and parentheses in extracted report text' do
    Dir.mktmpdir('pdf-escape-audit-') do |dir|
      title = 'Fixture C:\\new\\report(1)'
      path = described_class.generate(path: File.join(dir, 'fixture.pdf'), results_hash: { title: title, findings: [] })
      expect(PDF::Reader.new(path).pages.first.text).to include(title)
    end
  end

  it 'should display information for authors' do
    authors_response = PWN::Reports::PDF
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Reports::PDF
    expect(help_response).to respond_to :help
  end

  it 'should respond to generate' do
    expect(PWN::Reports::PDF).to respond_to :generate
  end
end
