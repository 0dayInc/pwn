# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::Findings do
  before do
    @dir = Dir.mktmpdir
    allow(Dir).to receive(:home).and_return(@dir)
    stub_const('PWN::Plugins::Findings::FILE', File.join(@dir, 'findings.jsonl'))
    stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(@dir, 'artifacts'))
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
    expect(row[:severity]).to eq('info')
    expect(row[:verification_status]).to eq('not_executed')
    expect(described_class.report(engagement_id: 'fixture').first).to include(finding)
    expect(described_class.report(engagement_id: 'other')).to eq([])
  end

  it 'persists directed enables links and replaces outgoing links durably' do
    target = described_class.record_structured(finding)
    source = described_class.record_structured(finding.merge(enables: [target[:id]]))
    expect(target[:enables]).to eq([])
    expect(described_class.report.find { |row| row[:id] == source[:id] }[:enables]).to eq([target[:id]])
    expect(described_class.link(id: source[:id], enables: [])[:enables]).to eq([])
    expect(described_class.report.find { |row| row[:id] == source[:id] }[:enables]).to eq([])
  end

  it 'rejects invalid outgoing links and cycles including legacy incoming links without mutation' do
    a = described_class.record_structured(finding)
    b = described_class.record_structured(finding.merge(attack_chain_refs: [a[:id]]))
    other = described_class.record_structured(finding.merge(engagement_id: 'other'))
    before = File.read(described_class::FILE)
    [nil, 'bad', [123], ['missing'], [a[:id]], [b[:id], b[:id]], [other[:id]]].each do |enables|
      expect { described_class.link(id: a[:id], enables: enables) }.to raise_error(ArgumentError)
    end
    expect { described_class.link(id: b[:id], enables: [a[:id]]) }.to raise_error(ArgumentError, /cycle/)
    expect { described_class.record_structured(finding.merge(enables: [b[:id]], attack_chain_refs: [b[:id]])) }.to raise_error(ArgumentError, /cycle/)
    expect { described_class.record_structured(finding.merge(enables: [other[:id]])) }.to raise_error(ArgumentError, /engagement/)
    expect { described_class.record_structured(finding.merge(enables: [b[:id], b[:id]])) }.to raise_error(ArgumentError, /duplicate/)
    expect(File.read(described_class::FILE)).to eq(before)
  end

  it 'treats empty and default engagement identifiers as the same graph scope' do
    a = described_class.record_structured(finding.merge(engagement_id: ''))
    b = described_class.record_structured(finding.merge(engagement_id: 'default', enables: [a[:id]]))
    c = described_class.record_structured(finding.merge(engagement_id: 'default', attack_chain_refs: [a[:id]]))
    expect(c[:attack_chain_refs]).to eq([a[:id]])
    expect(b[:enables]).to eq([a[:id]])
    expect { described_class.link(id: a[:id], enables: [b[:id]]) }.to raise_error(ArgumentError, /cycle/)
  end

  it 'links artifact handles to durable evidence hashes, reproduction steps and severity justification' do
    stored = PWN::Plugins::ArtifactRegistry.spill(bytes: "crash\x00\xff".b, session_id: 'fixture')
    args = finding.except(:evidence_paths).merge(
      artifact_handles: [{ handle: stored[:handle], kind: 'crash', label: 'crash.bin' }],
      severity_justification: 'The fixture leaks data without authentication; no integrity or availability impact demonstrated.',
      reproduction_steps: ['Start the local fixture.', 'Run the supplied PoC and compare its output.']
    )
    row = described_class.record_structured(args)
    expect(row[:severity_justification]).to eq(args[:severity_justification])
    expect(row[:reproduction_steps]).to eq(args[:reproduction_steps])
    evidence = row.fetch(:evidence_artifacts).first
    expect(evidence).to include(handle: stored[:handle], path: stored[:path], sha256: stored[:sha256], kind: 'crash')
    expect(File.binread(evidence[:stored])).to eq("crash\x00\xff".b)
    expect(described_class.report.first[:evidence_artifacts]).to eq(row[:evidence_artifacts])
    expect(row[:verification_status]).to eq('not_executed')
  end

  it 'flags removed evidence and rejects malformed metrics with trailing tokens' do
    described_class.record_structured(finding)
    File.delete(@evidence)
    expect(described_class.evidence_verify(engagement_id: 'fixture')[:ok]).to be(false)
    File.write(@evidence, 'fixture restored')
    expect { described_class.record_structured(finding.merge(cvss_vector: finding[:cvss_vector].sub('AV:N', 'AV:N:extra'))) }.to raise_error(ArgumentError, /cvss_vector/)
  end

  it 'detects tampering of the durable copy even when the original evidence still matches' do
    row = described_class.record_structured(finding)
    stored = row[:evidence_artifacts].first[:stored]
    File.binwrite(stored, 'corrupted stored bytes')
    expect(described_class.evidence_verify(engagement_id: 'fixture')).to include(ok: false, mismatches: include(stored))
  end

  it 'refuses a symlink masquerading as a durable evidence copy' do
    sha = Digest::SHA256.file(@evidence).hexdigest
    stored = File.join(@dir, '.pwn', 'engagements', 'fixture', 'evidence', sha)
    FileUtils.mkdir_p(File.dirname(stored))
    File.symlink(@evidence, stored)
    expect { described_class.record_structured(finding) }.to raise_error(ArgumentError, /symlink/)
    expect(described_class.report).to eq([])
  end

  it 'rejects invalid, missing, symlinked or changed handles without recording a finding' do
    artifact = PWN::Plugins::ArtifactRegistry.spill(bytes: 'original', session_id: 'fixture')
    args = finding.except(:evidence_paths).merge(artifact_handles: [artifact[:handle]], severity_justification: 'Read-only exposure.')
    ['../fixture/00000000.bin', 'fixture/00000000.bin', "#{artifact[:handle]}\n"].each do |handle|
      expect { described_class.record_structured(args.merge(artifact_handles: [handle])) }.to raise_error(ArgumentError, /handle/)
    end
    File.unlink(artifact[:path])
    File.symlink(@evidence, artifact[:path])
    expect { described_class.record_structured(args) }.to raise_error(ArgumentError, /symlink/)
    File.unlink(artifact[:path])
    File.binwrite(artifact[:path], 'changed')
    expect { described_class.record_structured(args) }.to raise_error(ArgumentError, /digest mismatch/)
    expect(described_class.report).to eq([])
  end

  it 'accepts legacy full hash handles and preserves an expected digest supplied with a descriptor' do
    artifact = PWN::Plugins::ArtifactRegistry.put(bytes: 'puts :fixture')
    args = finding.except(:evidence_paths).merge(artifact_handles: [artifact[:sha256]], severity_justification: 'Read-only exposure.')
    row = described_class.record_structured(args)
    expect(row[:evidence_artifacts].first).to include(handle: artifact[:sha256], sha256: artifact[:sha256])
    descriptor = { handle: artifact[:handle], sha256: '0' * 64 }
    expect { described_class.record_structured(args.merge(artifact_handles: [descriptor])) }.to raise_error(ArgumentError, /sha256 mismatch/)
    expect { described_class.record_structured(args.merge(severity_justification: ' ')) }.to raise_error(ArgumentError, /severity_justification/)
    [[], [''], 'run a command', [123]].each do |steps|
      expect { described_class.record_structured(args.merge(reproduction_steps: steps)) }.to raise_error(ArgumentError, /reproduction_steps/)
    end
  end

  it 'rejects a score inconsistent with the vector and unsafe engagement paths' do
    expect { described_class.record_structured(finding.merge(cvss_score: 9.8)) }.to raise_error(ArgumentError, /cvss_score/)
    expect { described_class.record_structured(finding.merge(engagement_id: '../escape')) }.to raise_error(ArgumentError, /engagement_id/)
  end

  it 'renders linked findings in all formats without inventing escalation' do
    parent = described_class.record_structured(finding)
    child = described_class.record_structured(finding.merge(title: '<script>fixture</script>', attack_chain_refs: [parent[:id]]))
    score = described_class.chain_score(ids: [parent[:id], child[:id]])
    expect(score[:combined_severity]).to eq('info')
    expect(score[:rationale]).to include('No automatic escalation')
    outputs = described_class.render(dir_path: @dir, engagement_id: 'fixture')
    json = JSON.parse(File.read(outputs[:json]))
    expect(json['attack_chains'].first['finding_ids']).to contain_exactly(parent[:id], child[:id])
    expect(json['attack_chains'].first['combined_severity']).to eq('info')
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

  it 'marks a finding reproduced only when the stored PoC prints the impact' do
    script = File.join(@dir, 'poc.sh')
    File.write(script, "#!/bin/sh\nprintf 'uid=0(root) fixture\\n'\n")
    File.chmod(0o755, script)
    row = described_class.record_structured(finding.merge(poc: script, reproduction_steps: [script]))
    planted = File.join(@dir, 'res.txt')
    File.write(planted, "HTTP/1.1 200 OK\n\nuid=0(root) fixture")
    verified = described_class.verify(id: row[:id], kind: 'script', impact: 'uid=0', request_path: planted, response_path: planted)
    expect(verified[:verification_status]).to eq('reproduced')
    expect(verified[:severity]).to eq('medium')
    expect(described_class.report(engagement_id: 'fixture').first[:verification_status]).to eq('reproduced')
    File.write(script, "#!/bin/sh\nprintf 'denied\\n'\n")
    retest = described_class.retest(id: row[:id], kind: 'script', impact: 'uid=0')
    expect(retest[:verification_status]).to eq('fixed')
    expect(retest[:status]).to eq('closed')
  end

  it 'persists path-scoped impact assessments with actual evidence and only consecutive directed edges' do
    a = described_class.record_structured(finding.merge(title: 'SSRF', cwe: 'CWE-918'))
    b = described_class.record_structured(finding.merge(title: 'Internal admin'))
    c = described_class.record_structured(finding.merge(title: 'Command execution'))
    d = described_class.record_structured(finding.merge(title: 'Alternate entry'))
    ids = [a[:id], b[:id], c[:id]]
    path = File.join(@dir, 'chain.txt')
    text = "Fixture replay #{ids.join(' -> ')}: SSRF reaches internal admin and executes the fixture command."
    File.write(path, text)
    result = described_class.chain_impact(ids: ids, combined_impact_path: path, escalate: true, combined_severity: 'critical')
    expect(result[:rationale]).to eq(text)
    rows = described_class.report.to_h { |row| [row[:id], row] }
    expect(rows[a[:id]][:enables]).to eq([b[:id]])
    expect(rows[b[:id]][:enables]).to eq([c[:id]])
    expect(rows[c[:id]][:attack_chain_refs]).to eq([])
    assessment = rows[c[:id]].fetch(:chain_assessments).first
    expect(assessment).to include(finding_ids: ids, combined_severity: 'critical', rationale: text,
                                  reproduction_steps: [a[:poc], b[:poc], c[:poc]])
    artifact = assessment[:evidence_artifacts].first
    expect(artifact).to include(path: path, sha256: Digest::SHA256.file(path).hexdigest, size: File.size(path))
    expect(File.read(artifact[:stored])).to eq(text)
    alternate = File.join(@dir, 'alternate.txt')
    File.write(alternate, "Fixture replay #{d[:id]} -> #{c[:id]} demonstrates read-only exposure, not command execution.")
    described_class.chain_impact(ids: [d[:id], c[:id]], combined_impact_path: alternate, escalate: true, combined_severity: 'high',
                                 severity_justification: 'Read-only internal exposure.', reproduction_steps: ['Replay alternate fixture.'])
    described_class.chain_impact(ids: ids, combined_impact_path: path, escalate: true, combined_severity: 'critical',
                                 severity_justification: 'Command execution proven in fixture.')
    assessments = described_class.report.find { |row| row[:id] == c[:id] }[:chain_assessments]
    expect(assessments.length).to eq(2)
    expect(assessments.find { |item| item[:finding_ids] == ids }[:rationale]).to eq('Command execution proven in fixture.')
    expect(assessments.find { |item| item[:finding_ids] == [d[:id], c[:id]] }).to include(combined_severity: 'high', reproduction_steps: ['Replay alternate fixture.'])
    expect(described_class.chain_score(ids: ids)[:combined_severity]).to eq('critical')
    expect(described_class.chain_score(ids: [d[:id], c[:id]])[:combined_severity]).to eq('high')
    expect(described_class.chain_score(ids: [b[:id], c[:id]])[:combined_severity]).to eq('info')
    expect(described_class.chain_score(ids: ids.reverse)[:combined_severity]).to eq('info')
  end

  it 'scores exact requested paths through the canonical graph without unrelated assessment uplift' do
    a = described_class.record_structured(finding.merge(title: 'SSRF', cwe: 'CWE-918'))
    b = described_class.record_structured(finding.merge(title: 'Internal admin'))
    other = described_class.record_structured(finding.merge(title: 'Other entry'))
    path = File.join(@dir, 'impact.txt')
    text = "Fixture replay #{a[:id]} -> #{b[:id]} proves SSRF reaches internal admin and executes a command."
    File.write(path, text)
    described_class.chain_impact(ids: [a[:id], b[:id]], combined_impact_path: path, escalate: true, combined_severity: 'critical')
    described_class.link(id: other[:id], enables: [b[:id]])
    allow(PWN::Reports).to receive(:attack_chains).and_call_original
    expect(PWN::Reports).to receive(:attack_chains).with(findings: array_including(hash_including(id: a[:id]), hash_including(id: b[:id]))).at_least(:once).and_call_original
    score = described_class.chain_score(ids: [a[:id], b[:id]])
    expect(score).to include(score: 'critical', combined_severity: 'critical', n: 2, rationale: text)
    expect(score[:chains].first).to include(finding_ids: [a[:id], b[:id]], assessment_status: 'evidence_backed')
    expect(described_class.chain_score(chain_refs: [other[:id], b[:id]])).to include(score: 'info', n: 2)
    expect(described_class.chain_score(ids: [b[:id]])).to include(score: 'info', n: 1)
    expect(described_class.chain_score(ids: ['missing'])).to include(score: 'info', n: 0)
    expect(described_class.chain_score[:combined_severity]).to eq('critical')
    expect(described_class.report.map { |row| row[:severity] }.uniq).to eq(['info'])
  end

  it 'rejects invalid impact paths before changing any finding or evidence ledger' do
    a = described_class.record_structured(finding)
    b = described_class.record_structured(finding.merge(enables: [a[:id]]))
    other = described_class.record_structured(finding.merge(engagement_id: 'other'))
    path = File.join(@dir, 'chain.txt')
    File.write(path, "Fixture replay #{a[:id]} #{b[:id]} #{other[:id]} includes all IDs but does not waive graph validation.")
    before = File.read(described_class::FILE)
    ledger = File.join(@dir, '.pwn', 'engagements', 'fixture', 'evidence.jsonl')
    evidence_before = File.read(ledger)
    [[a[:id], a[:id]], [a[:id], other[:id]], [a[:id], b[:id]], ['missing', a[:id]]].each do |ids|
      expect { described_class.chain_impact(ids: ids, combined_impact_path: path) }.to raise_error(ArgumentError)
    end
    expect(File.read(described_class::FILE)).to eq(before)
    expect(File.read(ledger)).to eq(evidence_before)
  end

  it 'rejects reverse links against legacy chain_refs and validates evidence before persisting impact' do
    a = described_class.record_structured(finding)
    legacy = described_class.record(title: 'Legacy child', severity: 'medium', engagement_id: 'fixture',
                                    poc_artifacts: [@evidence], chain_refs: [a[:id]],
                                    evidence: 'This local fixture is retained as the legacy finding evidence.')
    expect { described_class.link(id: legacy[:id], enables: [a[:id]]) }.to raise_error(ArgumentError, /cycle/)
    expect { described_class.link(id: 'missing', enables: []) }.to raise_error(ArgumentError, /existing/)
    path = File.join(@dir, 'impact-validation.txt')
    args = { ids: [a[:id], legacy[:id]], combined_impact_path: path, escalate: true, combined_severity: 'critical' }
    before = File.read(described_class::FILE)
    expect { described_class.chain_impact(args) }.to raise_error(ArgumentError, /readable/)
    ['', 'A long evidence file that still fails to mention either finding ID.'].each do |text|
      File.write(path, text)
      expect { described_class.chain_impact(args) }.to raise_error(ArgumentError, /name every/)
    end
    File.write(path, "Fixture #{a[:id]} -> #{legacy[:id]} demonstrates reproducible combined impact.")
    expect { described_class.chain_impact(args.merge(severity_justification: ' ')) }.to raise_error(ArgumentError, /severity_justification/)
    expect { described_class.chain_impact(args.merge(reproduction_steps: [])) }.to raise_error(ArgumentError, /reproduction_steps/)
    expect { described_class.chain_impact(args.merge(combined_severity: 'unknown')) }.to raise_error(ArgumentError, /combined_severity/)
    expect(File.read(described_class::FILE)).to eq(before)
  end

  it 'rejects a planted impact file and requires an executed transcript' do
    parent = described_class.record_structured(finding.merge(reproduction_steps: ["printf 'no-impact\\n'"]))
    child = described_class.record_structured(finding.merge(title: 'IDOR fixture', cwe: 'CWE-639', reproduction_steps: ["printf 'child\\n'"]))
    File.write(@evidence, 'uid=0')
    failed = described_class.verify(id: parent[:id], kind: 'script', request_path: @evidence, response_path: @evidence, impact: 'uid=0')
    expect(failed[:verification_status]).to eq('failed')
    impact = File.join(@dir, 'combined.txt')
    File.write(impact, "Chaining #{parent[:id]} with #{child[:id]} yields account takeover on the fixture.")
    chained = described_class.chain_impact(ids: [parent[:id], child[:id]], combined_impact_path: impact, escalate: true, combined_severity: 'high')
    expect(chained[:combined_severity]).to eq('high')
    expect(chained[:rationale]).to eq(File.read(impact))
    gaps = described_class.issue_work_gaps(engagement_id: 'fixture')
    expect(gaps[:unverified]).to include(child[:id])
    expect(gaps[:unverified]).not_to include(parent[:id])
  end
end
