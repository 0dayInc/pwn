# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::RedTeam::SupplyChain do
  it 'scan method should exist' do
    scan_response = PWN::AI::RedTeam::SupplyChain
    expect(scan_response).to respond_to :scan
  end

  it 'should display information for security_references' do
    security_references_response = PWN::AI::RedTeam::SupplyChain
    expect(security_references_response).to respond_to :security_references
  end

  it 'should display information for authors' do
    authors_response = PWN::AI::RedTeam::SupplyChain
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::RedTeam::SupplyChain
    expect(help_response).to respond_to :help
  end

  it 'defines strategies instead of a static attack_payloads list' do
    src = File.read(described_class.method(:scan).source_location.first)
    expect(src).to include('strategies = [')
    expect(src).not_to match(/attack_payloads\s*=\s*\[/)
    expect(src).to include('payload_count')
  end

  it 'maps an OWASP 2026 / ATLAS reference' do
    refs = described_class.security_references
    expect(refs[:section]).to include('LLM')
    expect(refs[:owasp_llm_uri]).to include('genai.owasp.org')
    expect(refs[:atlas_id]).to match(/\AAML\.T\d+\z/)
    expect(refs[:red_team_module]).to eq(described_class)
  end
end
