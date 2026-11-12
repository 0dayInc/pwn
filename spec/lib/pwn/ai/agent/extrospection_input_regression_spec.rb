# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Extrospection, 'OSINT input boundaries' do
  include_context 'pwn tmp sandbox'

  before do
    allow(described_class).to receive(:osint_api_keys).and_return({})
  end

  it 'extracts NANP groups from this phone number rather than the previous regexp match' do
    result = described_class.osint(query: '+12025550123', feeds: [:phone], record: false)
    expect(result.dig(:feeds, :phone, :nanp)).to eq(area_code: '202', nxx: '555', station: '0123')
  end

  it 'rejects resource-command injection before invoking a recon-ng process' do
    allow(described_class).to receive(:bridge_bin).and_return('/offline/recon-ng')
    allow(described_class).to receive(:sh).and_return('')
    result = described_class.osint(query: "example.test\nshell unexpected-command", feeds: [:reconng], record: false)
    expect(result.dig(:feeds, :reconng, :error)).to include('domain')
    expect(described_class).not_to have_received(:sh)
  end

  it 'retains valid email-to-domain bridge queries' do
    allow(described_class).to receive(:bridge_bin).and_return('/offline/recon-ng')
    allow(described_class).to receive(:sh).and_return('service.example.test')
    result = described_class.osint(query: 'analyst@example.test', feeds: [:reconng], record: false)
    expect(result.dig(:feeds, :reconng)).to include(domain: 'example.test', hosts: ['service.example.test'])
  end
end
