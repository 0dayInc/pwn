# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Extrospection, 'unavailable verification sources' do
  include_context 'pwn tmp sandbox'

  before do
    allow(described_class).to receive(:with_headless_browser).and_yield(:offline_browser)
    expect(PWN::AI::Agent::Mistakes).not_to receive(:record)
  end

  [nil, { reachable: false, status: 0, text: '' }, { reachable: false, status: 503, text: 'Service unavailable' }, { reachable: true, status: 200, text: '' }].each do |page|
    it "does not label a CVE confirmed or refuted from #{page.inspect}" do
      allow(described_class).to receive(:fingerprint_page) { page&.dup }
      result = described_class.verify(claim: 'CVE-2026-12345', kind: :cve, commit: false)
      expect(result).to include(verdict: :unknown, confidence: 0.0)
    end

    it "does not refute a document claim from #{page.inspect}" do
      allow(described_class).to receive(:fingerprint_page) { page&.dup }
      result = described_class.verify(claim: 'fixture documentation explains syntax', url: 'https://example.test/docs', commit: false)
      expect(result).to include(verdict: :unknown, confidence: 0.0)
    end
  end

  it 'still confirms a CVE using reachable source text' do
    allow(described_class).to receive(:fingerprint_page) do |opts|
      { reachable: true, status: 200, url: opts[:url], text: 'CVE-2026-12345 Description: Synthetic fixture product contains a memory safety flaw.' }
    end
    expect(described_class.verify(claim: 'CVE-2026-12345', commit: false)).to include(verdict: :confirmed)
  end

  it 'still refutes a missing document from an explicit not-found response' do
    allow(described_class).to receive(:fingerprint_page) { { reachable: false, status: 404, text: 'Not found' } }
    result = described_class.verify(claim: 'fixture documentation', url: 'https://example.test/missing', commit: false)
    expect(result).to include(verdict: :refuted)
  end
end
