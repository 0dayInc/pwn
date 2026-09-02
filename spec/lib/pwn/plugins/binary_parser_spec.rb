# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::BinaryParser do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'parses an ELF on this host' do
    path = %w[/bin/ls /usr/bin/ls /bin/true /usr/bin/true].find { |p| File.file?(p) }
    skip 'no ELF on PATH' unless path
    info = described_class.info(path: path)
    expect(info[:class].to_s).to match(/ELF|elf/i)
    expect(described_class.sections(path: path)).to be_an(Array)
  end

  it 'triage returns structured JSON fields and caches by sha256' do
    path = %w[/bin/ls /usr/bin/ls /bin/true /usr/bin/true].find { |p| File.file?(p) }
    skip 'no ELF on PATH' unless path
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      first = described_class.triage(path: path)
      expect(first).to include(:format, :arch, :protections, :sha256, :sections)
      expect(first[:cached]).to be false
      second = described_class.triage(path: path)
      expect(second[:cached]).to be true
    end
  end
end
