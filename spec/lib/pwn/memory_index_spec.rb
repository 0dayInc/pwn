# frozen_string_literal: true

require 'spec_helper'

describe PWN::MemoryIndex do
  it 'should display information for authors' do
    authors_response = PWN::MemoryIndex
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::MemoryIndex
    expect(help_response).to respond_to :help
  end

  it 'persists removal of forgotten memories when no remaining embedding changes' do
    Dir.mktmpdir('memory-index-') do |dir|
      stub_const('PWN::MemoryIndex::INDEX_FILE', File.join(dir, 'memory.idx'))
      allow(described_class).to receive(:embed).and_return([[1.0, 0.0]])
      memory = { fixture: { category: 'fact', value: 'fixture text' } }
      described_class.refresh(mem: memory)
      expect(described_class.refresh(mem: {})).to eq({})
      expect(JSON.parse(File.read(described_class::INDEX_FILE))).to eq({})
    end
  end

  it 'refreshes an embedding when the category changes with unchanged text' do
    Dir.mktmpdir('memory-index-') do |dir|
      stub_const('PWN::MemoryIndex::INDEX_FILE', File.join(dir, 'memory.idx'))
      allow(described_class).to receive(:embed).with(texts: ['fact: fixture text']).and_return([[1.0, 0.0]])
      allow(described_class).to receive(:embed).with(texts: ['lesson: fixture text']).and_return([[0.0, 1.0]])
      described_class.refresh(mem: { fixture: { category: 'fact', value: 'fixture text' } })
      updated = described_class.refresh(mem: { fixture: { category: 'lesson', value: 'fixture text' } })
      expect(updated.dig(:fixture, :vec)).to eq([0.0, 1.0])
      expect(described_class).to have_received(:embed).with(texts: ['lesson: fixture text']).once
    end
  end

  it 'ranks a throttle-evasion document above an unrelated document' do
    docs = [
      'the cat sat on the mat',
      'throttle evasion on the login form'
    ]
    ranked = described_class.bm25(query: 'bypass login rate limit', docs: docs)
    expect(ranked.first[:doc]).to include('throttle')
  end
end
