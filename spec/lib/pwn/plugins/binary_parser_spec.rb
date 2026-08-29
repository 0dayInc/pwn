# frozen_string_literal: true

require 'spec_helper'

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
end
