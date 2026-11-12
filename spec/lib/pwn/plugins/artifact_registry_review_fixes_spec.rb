# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::ArtifactRegistry, 'review containment regressions' do
  %i[root session index destination].each do |link|
    it "PSR-S01 rejects a #{link} symlink before copying or appending" do
      Dir.mktmpdir('artifact-containment') do |dir|
        root = File.join(dir, 'registry')
        session = File.join(root, 'safe')
        outside = File.join(dir, 'outside')
        FileUtils.mkdir_p([session, outside])
        source = File.join(dir, 'fixture.bin')
        File.binwrite(source, 'new bytes')
        sentinel = File.join(outside, 'sentinel')
        File.binwrite(sentinel, 'unchanged')
        target = { root: root, session: session, index: File.join(session, 'index.jsonl'),
                   destination: File.join(session, 'fixture.bin') }.fetch(link)
        FileUtils.remove_entry(target) if File.directory?(target)
        File.symlink(%i[root session].include?(link) ? outside : sentinel, target)
        stub_const('PWN::Plugins::ArtifactRegistry::ROOT', root)

        expect { described_class.register(session_id: 'safe', path: source) }.to raise_error(ArgumentError, /symlink/)
        expect(Dir.children(outside)).to eq(['sentinel'])
        expect(File.binread(sentinel)).to eq('unchanged')
        expect(File).not_to exist(File.join(session, 'fixture.bin')) unless link == :destination
      end
    end
  end

  %i[root session index].each do |link|
    it "PSR-S01 rejects a #{link} symlink before listing an external index" do
      Dir.mktmpdir('artifact-list-containment') do |dir|
        root = File.join(dir, 'registry')
        session = File.join(root, 'safe')
        outside = File.join(dir, 'outside')
        FileUtils.mkdir_p([session, File.join(outside, 'safe')])
        record = JSON.generate(path: 'external fixture')
        File.write(File.join(outside, 'index.jsonl'), record)
        File.write(File.join(outside, 'safe', 'index.jsonl'), record)
        target = { root: root, session: session, index: File.join(session, 'index.jsonl') }.fetch(link)
        FileUtils.remove_entry(target) if File.directory?(target)
        File.symlink(link == :index ? File.join(outside, 'index.jsonl') : outside, target)
        stub_const('PWN::Plugins::ArtifactRegistry::ROOT', root)

        expect { described_class.list(session_id: 'safe') }.to raise_error(ArgumentError, /symlink/)
      end
    end
  end

  it 'preserves successful registration and empty-list contracts' do
    Dir.mktmpdir('artifact-register') do |dir|
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'registry'))
      source = File.join(dir, 'fixture.bin')
      File.binwrite(source, 'fixture')
      expect(described_class.list(session_id: 'safe')).to eq([])
      dest = described_class.register(session_id: 'safe', path: source, kind: 'fixture')
      expect(File.binread(dest)).to eq('fixture')
      expect(described_class.list(session_id: 'safe')).to contain_exactly(hash_including(path: dest, src: source, kind: 'fixture'))
    end
  end
end
