# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'json'
require 'digest'

describe 'research evidence rules' do
  let(:dir) { Dir.mktmpdir('pwn-research-') }

  before do
    allow(Dir).to receive(:home).and_return(dir)
    stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
  end

  after { FileUtils.remove_entry(dir) if dir && Dir.exist?(dir) }

  it 'caps severity at info until a reproduced run, even when the PoC file hashes' do
    poc = File.join(dir, 'poc.sh')
    File.write(poc, "#!/bin/sh\nprintf 'nope\\n'\n")
    File.chmod(0o755, poc)
    row = PWN::Plugins::Findings.record(
      title: 'local proof', severity: 'critical', host: '127.0.0.1',
      poc_artifacts: [poc], evidence: 'PoC file is present and hashes, which is not execution proof.'
    )
    expect(row[:severity]).to eq('info')
    expect(row[:verification_status]).to eq('not_executed')
    planted = File.join(dir, 'already.txt')
    File.write(planted, 'uid=0')
    missed = PWN::Plugins::Findings.verify(id: row[:id], kind: 'script', impact: 'uid=0', request_path: planted, response_path: planted)
    expect(missed[:verification_status]).to eq('failed')
    File.write(poc, "#!/bin/sh\nprintf 'uid=0\\n'\n")
    proved = PWN::Plugins::Findings.verify(id: row[:id], kind: 'script', impact: 'uid=0')
    expect(proved[:verification_status]).to eq('reproduced')
    expect(proved[:severity]).to eq('critical')
    File.write(poc, "#!/bin/sh\nprintf 'fixed\\n'\n")
    retest = PWN::Plugins::Findings.retest(id: row[:id], kind: 'script', impact: 'uid=0')
    expect(retest[:verification_status]).to eq('fixed')
  end

  it 'refuses a short chain citation and does not raise composite severity above the parent' do
    poc = File.join(dir, 'poc.txt')
    File.write(poc, 'puts 1')
    parent = PWN::Plugins::Findings.record(
      title: 'xss', poc_artifacts: [poc], severity: 'high',
      evidence: 'PoC file reproduces reflected XSS in search; see artifact path.'
    )
    expect do
      PWN::Plugins::Findings.chain(parent_id: parent[:id], title: 'takeover', poc_artifacts: [poc], severity: 'critical')
    end.to raise_error(ArgumentError, /40/)
    child = PWN::Plugins::Findings.chain(
      parent_id: parent[:id], title: 'takeover', poc_artifacts: [poc], severity: 'critical',
      evidence: 'Child step is cited separately and does not by itself raise the parent severity.'
    )
    expect(child[:composite_severity]).to eq(parent[:severity])
  end

  it 'stores scanner leads as observations and skips a known port unless refresh is set' do
    PWN::Plugins::Recon.observe(host: '10.0.0.8', port: 443, product: 'nginx', version: '1.25', evidence_path: File.join(dir, 'banner.txt'), source: 'nmap', engagement_id: 'lab')
    File.write(File.join(dir, 'banner.txt'), 'nginx 1.25')
    skipped = PWN::Plugins::NmapIt.scan(target: '10.0.0.8', ports: [443], engagement: 'lab', override: true)
    expect(skipped[:scanned]).to eq(false)
    expect(skipped[:skipped_ports]).to eq([443])
    allow(PWN::Plugins::NmapIt).to receive(:port_scan)
    allow(PWN::Plugins::NmapIt).to receive(:inventory).and_return(hosts: [], ports: [])
    allow(PWN::Engagement).to receive(:merge_scan)
    allow(PWN::Engagement).to receive(:record_scan)
    allow(PWN::Engagement).to receive(:scans).and_return([])
    expect(PWN::Plugins::NmapIt).to receive(:port_scan)
    PWN::Plugins::NmapIt.scan(target: '10.0.0.8', ports: [443], engagement: 'lab', override: true, refresh: true, run: true)
  end

  it 'refuses to print a critical linked pair that was not reproduced' do
    path = File.join(dir, 'combined.txt')
    File.write(path, 'claimed combined impact without naming the findings')
    evidence = { stored: path, path: path, sha256: Digest::SHA256.file(path).hexdigest, size: File.size(path) }
    expect do
      PWN::Reports.report_payload(results_hash: {
                                    findings: [
                                      { id: 'a', title: 'A', severity: 'info', enables: ['b'] },
                                      { id: 'b', title: 'B', severity: 'info', chain_assessments: [
                                        { finding_ids: %w[a b], combined_severity: 'critical', rationale: 'claimed', evidence_artifacts: [evidence] }
                                      ] }
                                    ]
                                  })
    end.to raise_error(ArgumentError, /unverified linked pair/)
  end
end
