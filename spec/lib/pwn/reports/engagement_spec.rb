# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Reports::Engagement do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'isolates default findings from named engagements with symbol and string keys' do
    rows = [{ title: 'legacy' }, { 'title' => 'default row', 'engagement_id' => 'default' },
            { title: 'private alpha', engagement_id: 'alpha' }, { 'title' => 'private beta', 'engagement_id' => 'beta' }]
    allow(PWN::Plugins::Findings).to receive(:report).and_return(rows)
    Dir.mktmpdir do |dir|
      out = described_class.generate(dir_path: dir)
      data = JSON.parse(File.read(out[:json]))
      expect(data['findings'].map { |row| row['title'] }).to eq(['legacy', 'default row'])
      out = described_class.generate(engagement: 'beta', dir_path: dir)
      expect(JSON.parse(File.read(out[:json]))['findings'].map { |row| row['title'] }).to eq(['private beta'])
    end
  end

  it 'excludes explicitly supplied findings belonging to other engagements' do
    Dir.mktmpdir do |dir|
      out = described_class.generate(engagement: 'alpha', dir_path: dir, findings: [
                                       { title: 'implicit' }, { 'title' => 'selected', 'engagement_id' => 'alpha' },
                                       { title: 'other', engagement_id: 'beta' }
                                     ])
      expect(JSON.parse(File.read(out[:json]))['findings'].map { |row| row['title'] }).to eq(%w[implicit selected])
    end
  end

  it 'keeps finding evidence portable after moving the generated report bundle' do
    Dir.mktmpdir do |dir|
      stored = File.join(dir, 'stored')
      bytes = "raise 'Do not execute this fixture'"
      File.write(stored, bytes)
      evidence = { kind: 'poc', handle: 'artifact:fixture', label: '../fixture.rb', stored: stored,
                   sha256: Digest::SHA256.hexdigest(bytes), size: bytes.bytesize, finding_id: 'f1', ts: 'fixture-time' }
      bundle = File.join(dir, 'bundle')
      out = described_class.generate(engagement: 'lab', dir_path: bundle, findings: [
                                       { id: 'f1', engagement_id: 'lab', title: 'fixture', poc: bytes,
                                         reproduction_steps: ['Run fixture in lab', 'Observe output'], severity_justification: 'Fixture only',
                                         evidence_artifacts: [evidence], legacy_field: 'preserved' }
                                     ])
      moved = File.join(dir, 'moved')
      FileUtils.mv(bundle, moved)
      File.unlink(stored)
      row = JSON.parse(File.read(File.join(moved, File.basename(out[:json]))))['findings'].first
      exported = row['evidence_artifacts'].first
      expect(exported).to include('handle' => 'artifact:fixture', 'finding_id' => 'f1', 'ts' => 'fixture-time')
      expect(row['legacy_field']).to eq('preserved')
      expect(File.binread(File.join(moved, exported['attachment']))).to eq(bytes)
      %i[html markdown].each do |format|
        text = File.read(File.join(moved, File.basename(out[format])))
        expect(text).to include(exported['attachment'], evidence[:sha256], 'Fixture only', 'Observe output')
      end
    end
  end

  it 'writes html for two findings with poc paths' do
    Dir.mktmpdir do |dir|
      poc = File.join(dir, 'poc.rb')
      File.write(poc, 'puts 1')
      out = described_class.generate(
        engagement: 'lab',
        dir_path: dir,
        findings: [
          { title: 'a', severity: 'high', poc: poc },
          { title: 'b', severity: 'low', poc: poc }
        ]
      )
      expect(File.file?(out[:html])).to eq(true)
    end
  end
end
