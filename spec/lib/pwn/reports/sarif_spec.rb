# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'tmpdir'

describe PWN::Reports::SARIF do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'writes a SARIF 2.1 document with finding results' do
    Dir.mktmpdir do |dir|
      path = described_class.generate(
        results_hash: { title: 't', findings: [{ id: 'a1', title: 'xss', severity: 'high' }] },
        dir_path: dir,
        report_name: 'eng'
      )
      doc = JSON.parse(File.read(path))
      expect(doc['version']).to eq('2.1.0')
      expect(doc['runs'].first['results'].first['message']['text']).to eq('xss')
    end
  end
end
