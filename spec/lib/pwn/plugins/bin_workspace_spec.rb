# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::BinWorkspace do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'persists annotations by sha256 across opens' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::BinWorkspace::ROOT', File.join(dir, '.pwn', 'binws'))
      bin = File.join(dir, 'a.bin')
      File.binwrite(bin, 'ELF')
      described_class.annotate(path: bin, addr: '0x401000', kind: 'rename', name: 'win')
      notes = described_class.notes(path: bin)
      expect(notes[:'0x401000'][:name]).to eq('win')
    end
  end
end
