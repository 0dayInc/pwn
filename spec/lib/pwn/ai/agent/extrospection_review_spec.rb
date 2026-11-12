# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::AI::Agent::Extrospection, 'canonical verification review' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    allow(described_class).to receive(:tls_fingerprint).and_return([nil, nil])
  end

  def serve_html(html, status = 200)
    response = double('offline HTTP response', body: html, code: status, headers: {})
    browser = double('offline HTTP client')
    allow(browser).to receive(:get).and_yield(response, nil, nil)
    allow(described_class).to receive(:with_headless_browser).and_yield(type: :rest, browser: browser)
  end

  [
    '<title>Maintenance</title><p>Temporarily unavailable; retry later.</p>',
    '<title>CVE-2026-12345</title><p>Please sign in to continue.</p>',
    '<h1>CVE-2026-12345</h1><p>Checking your browser before accessing the record.</p>',
    '<h1>CVE-2026-54321</h1><h2>Description</h2><p>Synthetic product contains a memory safety flaw.</p>',
    '<h1>CVE-2026-12345</h1><p>Details</p>',
    '<title>Maintenance</title><h1>CVE-2026-12345</h1><h2>Description</h2><p>Service is undergoing planned maintenance.</p>'
  ].each do |html|
    it "keeps noncanonical 200 content unknown: #{html}" do
      serve_html(html)
      expect(described_class.verify(claim: 'CVE-2026-12345', commit: false)).to include(verdict: :unknown, confidence: 0.0)
    end
  end

  it 'persists unavailable-source decisions as unknown with evidence provenance' do
    serve_html('<title>Unavailable</title><p>Offline fixture</p>', 503)
    result = described_class.verify(claim: 'CVE-2026-12345', commit: true)
    expect(result).to include(verdict: :unknown, action_taken: :learning_note)
    learning = PWN::AI::Agent::Learning
    expect(learning.outcomes(success: false)).to be_empty
    expect(learning.outcomes(success: true)).to be_empty
    row = learning.outcomes.first
    expect(row).to include(success: nil, verdict: 'unknown', training_score: nil, decision_version: 1, status: 'unverified')
    expect(row.dig(:grounded, :evidence).map { |page| page[:status] }).to eq([503, 503])
  end

  it 'persists an unknown decision when the browser source itself is unavailable' do
    allow(described_class).to receive(:with_headless_browser).and_raise(IOError, 'offline browser unavailable')
    result = described_class.verify(claim: 'CVE-2026-12345', commit: true)
    expect(result).to include(verdict: :unknown, action_taken: :learning_note)
    row = PWN::AI::Agent::Learning.outcomes.first
    expect(row).to include(training_score: nil, status: 'unverified', verdict: 'unknown')
    expect(PWN::AI::Agent::Learning.outcomes(success: false)).to be_empty
  end

  it 'confirms record identity only when canonical description content exists' do
    serve_html('<h1>CVE-2026-12345</h1><h2>Description</h2><p data-testid="vuln-description">Synthetic fixture product contains a memory safety flaw.</p>')
    result = described_class.verify(claim: 'CVE-2026-12345', commit: false)
    expect(result).to include(verdict: :confirmed)
    expect(result[:evidence].map { |row| row[:dom_sha] }).to all(match(/\A[0-9a-f]{16}\z/))
  end
end
