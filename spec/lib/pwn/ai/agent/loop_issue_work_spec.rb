# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Agent::Loop, 'issue work verification' do
  it 'keeps issue_work unsatisfied when recorded findings were never reproduced' do
    dir = Dir.mktmpdir
    allow(Dir).to receive(:home).and_return(dir)
    stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
    evidence = File.join(dir, 'ev.txt')
    File.write(evidence, 'Local fixture returned the reproducible response.')
    PWN::Plugins::Findings.record_structured(
      title: 'Fixture exposure', cwe: 'CWE-200', cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
      cvss_score: 5.3, affected_asset: 'asset-fixture', evidence_paths: [evidence],
      poc: 'curl http://127.0.0.1:8000/', attack_chain_refs: [], remediation: 'Restrict fixture access.',
      confidence: 0.9, engagement_id: 'loop-fixture'
    )
    poc = File.join(dir, 'poc.txt')
    File.write(poc, 'working poc')
    Thread.current[:pwn_loop_deliverables] = {
      paths: [], min_seconds: 0, skills: [], proofs: [poc], hosts: [], techniques: [], issue_work: true
    }
    expect(
      described_class.send(:completion_unmet, request: 'hunt issues', messages: [{ role: 'tool', content: 'recorded' }])
    ).to include('issue_work_unverified')
  ensure
    FileUtils.remove_entry(dir) if defined?(dir)
    Thread.current[:pwn_loop_deliverables] = nil
  end
end
