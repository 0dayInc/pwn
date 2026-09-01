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

  it 'ranks a throttle-evasion document above an unrelated document' do
    docs = [
      'the cat sat on the mat',
      'throttle evasion on the login form'
    ]
    ranked = described_class.bm25(query: 'bypass login rate limit', docs: docs)
    expect(ranked.first[:doc]).to include('throttle')
  end
end
