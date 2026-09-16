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

  it 'resolves a named builtin corpus from cache' do
    Dir.mktmpdir('corpus') do |dir|
      stub_const('PWN::Corpus::ROOT', dir)
      path = described_class.get(name: :fuzz_short, offline: true)
      expect(File.read(path)).to include('../')
      expect(described_class.get(name: :fuzz_short, offline: true)).to eq(path)
    end
  end
end
