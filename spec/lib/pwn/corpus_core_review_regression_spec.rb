# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'PWN::Corpus P1 publication recovery' do
  before do
    @corpus_dir = Dir.mktmpdir('pwn-corpus-recovery-')
    stub_const('PWN::Corpus::ROOT', @corpus_dir)
    allow(Net::HTTP).to receive(:get).and_return("old fixture\n", "new fixture\n")
  end

  after do
    FileUtils.remove_entry(@corpus_dir)
  end

  %i[data checksum].product(%i[before after]).each do |file, timing|
    it "restores the readable pair when publication raises #{timing} replacing #{file}" do
      path = PWN::Corpus.get(name: :subdomains_top1m)
      old_data = File.binread(path)
      old_checksum = File.binread("#{path}.sha256")
      before = Dir.children(PWN::Corpus::ROOT).sort
      target = file == :data ? path : "#{path}.sha256"
      allow(FileUtils).to receive(:mv).and_wrap_original do |original, source, destination|
        raise Errno::EACCES, 'synthetic publication failure' if destination == target && timing == :before

        result = original.call(source, destination)
        raise Errno::EACCES, 'synthetic publication failure' if destination == target && timing == :after

        result
      end
      expect { PWN::Corpus.update(name: :subdomains_top1m) }.to raise_error(Errno::EACCES, /synthetic publication failure/)
      expect(PWN::Corpus.get(name: :subdomains_top1m, offline: true)).to eq(path)
      expect(File.binread(path)).to eq(old_data)
      expect(File.binread("#{path}.sha256")).to eq(old_checksum)
      expect(Dir.children(PWN::Corpus::ROOT).sort).to eq(before)
    end
  end

  it 'removes partial new publication on an initial update failure' do
    allow(FileUtils).to receive(:mv).and_wrap_original do |original, source, destination|
      raise Errno::EACCES, 'synthetic checksum failure' if destination.end_with?('.sha256')

      original.call(source, destination)
    end
    expect { PWN::Corpus.update(name: :subdomains_top1m) }.to raise_error(Errno::EACCES)
    expect(Dir.children(PWN::Corpus::ROOT)).to be_empty
    expect { PWN::Corpus.get(name: :subdomains_top1m, offline: true) }.to raise_error(IOError, /cache miss/)
  end

  it 'preserves unowned legacy temporary paths on successful publication' do
    path = PWN::Corpus.get(name: :subdomains_top1m)
    File.write("#{path}.tmp", 'unowned data')
    File.write("#{path}.tmp.sha256", 'unowned checksum')
    before = Dir.children(PWN::Corpus::ROOT).sort
    expect(PWN::Corpus.update(name: :subdomains_top1m)).to eq(path)
    expect(PWN::Corpus.get(name: :subdomains_top1m, offline: true)).to eq(path)
    expect(File.binread(path)).to eq("new fixture\n")
    expect(File.binread("#{path}.tmp")).to eq('unowned data')
    expect(File.binread("#{path}.tmp.sha256")).to eq('unowned checksum')
    expect(Dir.children(PWN::Corpus::ROOT).sort).to eq(before)
  end

  it 'retains recovery copies if rollback itself cannot restore a file' do
    path = PWN::Corpus.get(name: :subdomains_top1m)
    old_checksum = File.binread("#{path}.sha256")
    allow(FileUtils).to receive(:mv).and_wrap_original do |original, source, destination|
      raise Errno::EACCES, 'synthetic checksum failure' if destination.end_with?('.sha256')

      original.call(source, destination)
    end
    allow(File).to receive(:rename).and_wrap_original do |original, source, destination|
      raise Errno::EIO, 'synthetic rollback failure' if destination == path && File.basename(source) == File.basename(path)

      original.call(source, destination)
    end
    expect { PWN::Corpus.update(name: :subdomains_top1m) }.to raise_error(Errno::EIO, /synthetic rollback failure/)
    copies = Dir.glob(File.join(PWN::Corpus::ROOT, '.corpus-update-*', File.basename(path)))
    expect(copies.length).to eq(1)
    expect(File.binread(copies.first)).to eq("old fixture\n")
    expect(File.binread("#{copies.first}.sha256")).to eq(old_checksum)
  end

  it 'cleans its staged files when preparing the checksum raises' do
    path = PWN::Corpus.get(name: :subdomains_top1m)
    before = Dir.children(PWN::Corpus::ROOT).sort
    allow(File).to receive(:write).and_wrap_original do |original, target, body|
      raise Errno::ENOSPC, 'synthetic staging failure' if target.end_with?('.tmp.sha256')

      original.call(target, body)
    end
    expect { PWN::Corpus.update(name: :subdomains_top1m) }.to raise_error(Errno::ENOSPC)
    expect(PWN::Corpus.get(name: :subdomains_top1m, offline: true)).to eq(path)
    expect(File.binread(path)).to eq("old fixture\n")
    expect(Dir.children(PWN::Corpus::ROOT).sort).to eq(before)
  end
end
