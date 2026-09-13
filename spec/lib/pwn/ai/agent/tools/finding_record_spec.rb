# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools finding_record' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/finding_record.rb'
  end

  it 'rejects missing PoC even with legacy artifacts at the agent boundary' do
    handler = PWN::AI::Agent::Registry.lookup(name: 'finding_record').handler
    expect { handler.call('title' => 'fixture', 'poc_artifacts' => ['/tmp/legacy']) }.to raise_error(ArgumentError)
    fields = PWN::AI::Agent::Registry.lookup(name: 'finding_record').schema[:parameters][:properties]
    expect(fields.keys).to include(:cwe, :cvss_score, :cvss_vector, :evidence_paths, :attack_chain_refs, :remediation, :confidence)
    contract = PWN::AI::Agent::Registry.lookup(name: 'finding_record').schema[:parameters][:anyOf]
    expect(contract.last[:required]).to include('poc', 'cwe', 'cvss_score', 'evidence_paths')
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'finding_record')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'finding_report')).not_to be_nil
  end

  it 'exposes verify retest and chain_impact operations' do
    fields = PWN::AI::Agent::Registry.lookup(name: 'finding_record').schema[:parameters][:properties]
    expect(fields[:op][:enum]).to include('verify', 'retest', 'chain_impact', 'gaps')
  end
end
