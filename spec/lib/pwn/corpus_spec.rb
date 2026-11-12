# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'

describe PWN::Corpus do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'keeps a refreshed corpus readable by offline callers with its new checksum' do
    Dir.mktmpdir('corpus-refresh-') do |dir|
      stub_const('PWN::Corpus::ROOT', dir)
      allow(Net::HTTP).to receive(:get).and_return("old fixture\n", "new fixture\n")
      path = described_class.get(name: :subdomains_top1m)
      expect(described_class.update(name: :subdomains_top1m)).to eq(path)
      expect(described_class.get(name: :subdomains_top1m, offline: true)).to eq(path)
      expect(File.read(path)).to eq("new fixture\n")
      expect(File.read("#{path}.sha256")).to eq(Digest::SHA256.file(path).hexdigest)
      expect(Dir.glob(File.join(dir, '*.tmp*'))).to be_empty
    end
  end

  it 'resolves a named builtin corpus from cache' do
    Dir.mktmpdir('corpus') do |dir|
      stub_const('PWN::Corpus::ROOT', dir)
      path = described_class.get(name: :fuzz_short, offline: true)
      expect(File.read(path)).to include('../')
      expect(described_class.get(name: :fuzz_short, offline: true)).to eq(path)
    end
  end
end
