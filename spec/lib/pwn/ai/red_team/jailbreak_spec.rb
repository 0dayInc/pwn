# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::RedTeam::Jailbreak do
  it 'scan method should exist' do
    scan_response = PWN::AI::RedTeam::Jailbreak
    expect(scan_response).to respond_to :scan
  end

  it 'should display information for security_references' do
    security_references_response = PWN::AI::RedTeam::Jailbreak
    expect(security_references_response).to respond_to :security_references
  end

  it 'should display information for authors' do
    authors_response = PWN::AI::RedTeam::Jailbreak
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::RedTeam::Jailbreak
    expect(help_response).to respond_to :help
  end
  it 'defines strategies instead of a static attack_payloads list' do
    src = File.read(described_class.method(:scan).source_location.first)
    expect(src).to include('strategies = [')
    expect(src).not_to match(/attack_payloads\s*=\s*\[/)
    expect(src).to include('payload_count')
  end
end
