# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::Findings do
  before do
    @dir = Dir.mktmpdir
    allow(Dir).to receive(:home).and_return(@dir)
    stub_const('PWN::Plugins::Findings::FILE', File.join(@dir, 'findings.jsonl'))
    @evidence = File.join(@dir, 'response.txt')
    File.write(@evidence, 'Local fixture returned the reproducible response.')
  end

  after { FileUtils.remove_entry(@dir) }

  let(:finding) do
    { title: 'Fixture exposure', cwe: 'CWE-200', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
      cvss_score: 5.3, affected_asset: 'asset-fixture', evidence_paths: [@evidence],
      poc: 'curl http://127.0.0.1:8000/', attack_chain_refs: [], remediation: 'Restrict fixture access.', confidence: 0.9,
      engagement_id: 'fixture' }
  end

  it 'persists the complete structured contract without treating file existence as PoC execution' do
    row = described_class.record_structured(finding)
    expect(row).to include(finding)
    expect(row[:severity]).to eq('medium')
    expect(row[:verification_status]).to eq('not_executed')
    expect(described_class.report(engagement_id: 'fixture').first).to include(finding)
    expect(described_class.report(engagement_id: 'other')).to eq([])
  end

  it 'flags removed evidence and rejects malformed metrics with trailing tokens' do
    described_class.record_structured(finding)
    File.delete(@evidence)
    expect(described_class.evidence_verify(engagement_id: 'fixture')[:ok]).to be(false)
    File.write(@evidence, 'fixture restored')
    expect { described_class.record_structured(finding.merge(cvss_vector: finding[:cvss_vector].sub('AV:N', 'AV:N:extra'))) }.to raise_error(ArgumentError, /cvss_vector/)
  end

  it 'rejects a score inconsistent with the vector and unsafe engagement paths' do
    expect { described_class.record_structured(finding.merge(cvss_score: 9.8)) }.to raise_error(ArgumentError, /cvss_score/)
    expect { described_class.record_structured(finding.merge(engagement_id: '../escape')) }.to raise_error(ArgumentError, /engagement_id/)
  end

  it 'renders linked findings in all formats without inventing escalation' do
    parent = described_class.record_structured(finding)
    child = described_class.record_structured(finding.merge(title: '<script>fixture</script>', attack_chain_refs: [parent[:id]]))
    score = described_class.chain_score(ids: [parent[:id], child[:id]])
    expect(score[:combined_severity]).to eq('medium')
    expect(score[:rationale]).to include('No automatic escalation')
    outputs = described_class.render(dir_path: @dir, engagement_id: 'fixture')
    json = JSON.parse(File.read(outputs[:json]))
    expect(json['attack_chains'].first['finding_ids']).to contain_exactly(parent[:id], child[:id])
    expect(json['attack_chains'].first['combined_severity']).to eq('medium')
    expect(File.read(outputs[:markdown])).to include('## Attack chains', parent[:id], 'No automatic escalation')
    html = File.read(outputs[:html])
    expect(html).to include('Attack chains', 'CWE-200', 'Restrict fixture access.', @evidence, '&lt;script&gt;')
    expect(html).not_to include('<script>fixture</script>')
  end

  it 'rejects invalid structured fields before any record is appended' do
    mutations = { poc: '', cwe: '200', cvss_score: 10.1, cvss_vector: 'CVSS:3.1/AV:Q',
                  evidence_paths: ['/nonexistent/pwn-evidence'], remediation: '', confidence: 1.1,
                  attack_chain_refs: ['missing'], affected_asset: '' }
    mutations.each do |key, value|
      expect { described_class.record_structured(finding.merge(key => value)) }.to raise_error(ArgumentError, /#{key}/)
    end
    expect { described_class.record_structured(finding.except(:poc)) }.to raise_error(ArgumentError, /poc/)
    expect(File.exist?(described_class::FILE)).to be(false)
  end

  it 'marks a finding reproduced only when request/response evidence contains the impact' do
    row = described_class.record_structured(finding)
    request = File.join(@dir, 'req.txt')
    response = File.join(@dir, 'res.txt')
    File.write(request, "GET /admin HTTP/1.1\nHost: 127.0.0.1")
    File.write(response, "HTTP/1.1 200 OK\n\nuid=0(root) fixture")
    verified = described_class.verify(id: row[:id], kind: 'http', request_path: request, response_path: response, impact: 'uid=0')
    expect(verified[:verification_status]).to eq('reproduced')
    expect(described_class.report(engagement_id: 'fixture').first[:verification_status]).to eq('reproduced')
    File.write(response, "HTTP/1.1 403 Forbidden\n\ndenied")
    retest = described_class.retest(id: row[:id], kind: 'http', request_path: request, response_path: response, impact: 'uid=0')
    expect(retest[:verification_status]).to eq('fixed')
    expect(retest[:status]).to eq('closed')
  end

  it 'rejects signature-only verification and requires combined-impact evidence to escalate a chain' do
    parent = described_class.record_structured(finding)
    child = described_class.record_structured(finding.merge(title: 'IDOR fixture', cwe: 'CWE-639'))
    expect { described_class.verify(id: parent[:id], kind: 'http', impact: 'uid=0') }.to raise_error(ArgumentError, /request_path/)
    expect(described_class.report(engagement_id: 'fixture').first[:verification_status]).to eq('not_executed')
    File.write(@evidence, 'Local fixture returned the reproducible response.')
    failed = described_class.verify(id: parent[:id], kind: 'http', request_path: @evidence, response_path: @evidence, impact: 'not-in-file')
    expect(failed[:verification_status]).to eq('failed')
    impact = File.join(@dir, 'combined.txt')
    File.write(impact, "Chaining #{parent[:id]} with #{child[:id]} yields account takeover on the fixture.")
    chained = described_class.chain_impact(ids: [parent[:id], child[:id]], combined_impact_path: impact, escalate: true, combined_severity: 'high')
    expect(chained[:combined_severity]).to eq('high')
    expect(chained[:rationale]).to include('independently evidenced')
    gaps = described_class.issue_work_gaps(engagement_id: 'fixture')
    expect(gaps[:unverified]).to include(child[:id])
    expect(gaps[:unverified]).not_to include(parent[:id])
  end
end
