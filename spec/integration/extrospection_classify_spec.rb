# frozen_string_literal: true

require 'spec_helper'

# ─────────────────────────────────────────────────────────────────────────────
#  #8 — the OSINT / verify / rf sense-organs can't run non-blocking, but
#  their pure-ruby CLASSIFIERS can — and mis-classification is where
#  they actually fail (an IP routed to :phone hits the wrong feed set).
#
#  NON-BLOCKING: only the private detect_* / compute_drift preambles are
#  exercised via `.send`; every network / browser path is stubbed to
#  raise so accidental invocation fails loudly.
# ─────────────────────────────────────────────────────────────────────────────

RSpec.describe 'PWN::AI::Agent::Extrospection — classifiers', :aggregate_failures do
  include_context 'pwn tmp sandbox'

  let(:extro) { PWN::AI::Agent::Extrospection }

  before do
    allow(extro).to receive(:with_headless_browser).and_raise('network hit — spec is not non-blocking')
    allow(extro).to receive(:http_get_json).and_raise('network hit — spec is not non-blocking')
  end

  describe 'detect_osint_kind (extro_osint kind: :auto)' do
    {
      '8.8.8.8' => :ip,
      '2001:4860:4860::8888' => :ip,
      '00:1A:2B:3C:4D:5E' => :mac,
      'user@example.com' => :email,
      'https://example.com/x' => :url,
      'CVE-2024-12345' => :cve,
      '1FTFW1ET1EFC12345' => :vin,
      'example.com' => :domain,
      '@handle' => :social,
      '@user@mastodon.social' => :social,
      '+13125551212' => :phone,
      '(312) 555-1212' => :phone,
      '2ABCD-XYZ1' => :fcc_id,
      'Acme Widgets Inc.' => :company,
      '123 Main St' => :geo,
      'john death record' => :vital_records,
      'torvalds' => :username,
      'Jane Q. Doe' => :person
    }.each do |q, kind|
      it "#{q.inspect} → :#{kind}" do
        expect(extro.send(:detect_osint_kind, query: q)).to eq(kind)
      end
    end

    it 'a BTC-address-shaped string is NOT classified as :phone' do
      expect(extro.send(:detect_osint_kind, query: '1HB5XMLmzFVj8ALj6mfBsbifRoD4miY36v')).not_to eq(:phone)
    end
  end

  describe 'detect_claim_kind (extro_verify kind auto-detect)' do
    it 'URL present → :doc' do
      expect(extro.send(:detect_claim_kind, claim: 'see https://example.com/x for details')).to eq(:doc)
      expect(extro.send(:detect_claim_kind, claim: 'quoted', url: 'https://x.test')).to eq(:doc)
    end

    it 'CVE-YYYY-NNNN → :cve' do
      expect(extro.send(:detect_claim_kind, claim: 'CVE-2024-12345 affects widget')).to eq(:cve)
    end

    it '"latest X is v1.2.3" → :version' do
      expect(extro.send(:detect_claim_kind, claim: 'latest nmap is 7.95')).to eq(:version)
    end

    it 'free text → :generic' do
      expect(extro.send(:detect_claim_kind, claim: 'the sky is blue')).to eq(:generic)
    end
  end

  describe 'compute_drift on hand-built hashes' do
    it 'returns dotted-path {changed:, added:, removed:} and ignores captured_at/fingerprint' do
      before_h = { captured_at: 't0', fingerprint: 'aaa',
                   toolchain: { nmap: '7.94' }, repo: { head: 'abc' }, gone: { x: 1 } }
      after_h  = { captured_at: 't1', fingerprint: 'bbb',
                   toolchain: { nmap: '7.95' }, repo: { head: 'abc' }, added: { y: 2 } }
      d = extro.send(:compute_drift, before: before_h, after: after_h)
      expect(d[:changed].map { |c| c[:path] }).to include('toolchain.nmap')
      expect(d[:changed].find { |c| c[:path] == 'toolchain.nmap' })
        .to include(before: '7.94', after: '7.95')
      expect(d[:added].map { |c| c[:path] }).to include('added.y')
      expect(d[:removed].map { |c| c[:path] }).to include('gone.x')
      expect(d[:changed].map { |c| c[:path] }).not_to include('captured_at', 'fingerprint')
    end
  end
end
