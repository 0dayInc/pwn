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
    expect(fields.keys).to include(:cwe, :cvss_score, :cvss_vector, :evidence_paths, :artifact_handles, :severity_justification, :reproduction_steps, :attack_chain_refs, :remediation, :confidence)
    contract = PWN::AI::Agent::Registry.lookup(name: 'finding_record').schema[:parameters][:anyOf]
    expect(contract.last[:required]).to include('poc', 'cwe', 'cvss_score', 'severity_justification', 'reproduction_steps')
  end

  it 'accepts handle-only findings through the registered schema and handler' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
      artifact = PWN::Plugins::ArtifactRegistry.spill(bytes: 'puts :fixture', session_id: 'fixture')
      args = { title: 'Fixture exposure', cwe: 'CWE-200', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
               cvss_score: 5.3, affected_asset: 'local fixture', poc: 'ruby poc.rb', attack_chain_refs: [],
               remediation: 'Restrict access.', confidence: 0.9, artifact_handles: [{ handle: artifact[:handle], kind: 'poc', label: 'poc.rb' }],
               severity_justification: 'Read-only data exposure; no availability impact demonstrated.',
               reproduction_steps: ['Start the fixture.', 'Run ruby poc.rb and inspect its output.'] }
      tool = PWN::AI::Agent::Registry.lookup(name: 'finding_record')
      schema = JSONSchemer.schema(JSON.parse(JSON.generate(tool.schema[:parameters])))
      expect(schema.valid?(JSON.parse(JSON.generate(args)))).to be(true)
      row = tool.handler.call(JSON.parse(JSON.generate(args)))
      expect(row[:evidence_artifacts].first).to include(handle: artifact[:handle], sha256: artifact[:sha256])
      expect(row[:reproduction_steps]).to eq(args[:reproduction_steps])
      dispatched = JSON.parse(PWN::AI::Agent::Dispatch.call(
                                tool_call: { function: { name: 'finding_record', arguments: JSON.generate(args) } },
                                scope_path: File.join(dir, 'absent.yaml'), session_id: 'fixture'
                              ), symbolize_names: true)
      expect(dispatched.dig(:result, :evidence_artifacts, 0)).to include(handle: artifact[:handle], sha256: artifact[:sha256])
      %i[severity_justification reproduction_steps].each do |key|
        expect(schema.valid?(JSON.parse(JSON.generate(args.except(key))))).to be(false)
        expect { tool.handler.call(args.except(key)) }.to raise_error(ArgumentError, /#{key}/)
      end
    end
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'finding_record')).not_to be_nil
    expect(PWN::AI::Agent::Registry.lookup(name: 'finding_report')).not_to be_nil
  end

  it 'exposes directed enables links and existing-finding link updates' do
    schema = PWN::AI::Agent::Registry.lookup(name: 'finding_record').schema[:parameters]
    expect(schema[:properties][:enables]).to include(type: 'array', uniqueItems: true)
    validator = JSONSchemer.schema(JSON.parse(JSON.generate(schema)))
    expect(validator.valid?({ 'op' => 'link', 'id' => 'ssrf', 'enables' => ['admin'] })).to be(true)
    expect(validator.valid?({ 'op' => 'link', 'id' => 'ssrf' })).to be(false)
    expect(validator.valid?({ 'op' => 'link', 'id' => 'ssrf', 'enables' => %w[admin admin] })).to be(false)
  end

  it 'exposes verify retest and chain_impact operations' do
    fields = PWN::AI::Agent::Registry.lookup(name: 'finding_record').schema[:parameters][:properties]
    expect(fields[:op][:enum]).to include('verify', 'retest', 'chain_impact', 'gaps')
    schema = JSONSchemer.schema(JSON.parse(JSON.generate(PWN::AI::Agent::Registry.lookup(name: 'finding_record').schema[:parameters])))
    %w[verify retest].each do |op|
      expect(schema.valid?({ 'op' => op, 'id' => 'fixture', 'kind' => 'script', 'execution_log' => '/tmp/output.log', 'impact' => 'fixture impact' })).to be(true)
    end
    expect(schema.valid?({ 'op' => 'gaps' })).to be(true)
    expect(schema.valid?({ 'op' => 'chain_impact', 'ids' => %w[parent child], 'combined_impact_path' => '/tmp/chain.txt' })).to be(true)
  end
end
