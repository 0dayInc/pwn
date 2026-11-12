# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::AI::Agent::Learning, 'lifecycle publication compatibility' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    root = File.join(@tmp, '.pwn')
    FileUtils.mkdir_p(root)
    stub_const('PWN::Sessions::SESSIONS_DIR', File.join(root, 'sessions'))
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(root, 'learning.jsonl'))
  end

  [false, true].each do |dry|
    ['{unparseable evidence', '[1,2]'].each do |invalid|
      it "AI-LR-L07 preserves uncertain evidence and reports a blocked #{dry ? 'preview' : 'apply'} for #{invalid}" do
        good = JSON.generate(id: 'good', task: 'retained task', success: false, details: 'fixture', timestamp: '2020-01-01T00:00:00Z')
        bytes = "#{good}\n#{invalid}\n"
        File.write(described_class::LEARNING_FILE, bytes)
        inode = File.stat(described_class::LEARNING_FILE).ino
        result = described_class.prune_outcomes!(dry_run: dry)
        expect(File.binread(described_class::LEARNING_FILE)).to eq(bytes.b)
        expect(File.stat(described_class::LEARNING_FILE).ino).to eq(inode)
        expect(result).to include(state: 'blocked', aborted: true, malformed_rows: 1, removed: 0, kept: 2)
      end
    end
  end

  it 'binds archived PRM publication to the original turn through the actual Reward caller' do
    session = PWN::Sessions.create
    PWN::Sessions.append(session_id: session[:id], role: 'user', content: 'first request')
    PWN::Sessions.append(session_id: session[:id], role: 'tool', content: 'first tool')
    snapshot = PWN::AI::Agent::Reward.prm_snapshot(session_id: session[:id], request: 'first request')
    PWN::Sessions.append(session_id: session[:id], role: 'user', content: 'later request')
    PWN::Sessions.append(session_id: session[:id], role: 'tool', content: 'later tool')
    described_class.note_outcome(task: 'retained evidence', success: false, session_id: session[:id])
    described_class.migrate_evidence(dry_run: false)
    original_row = described_class.outcomes.first
    PWN::Sessions.delete(session_id: session[:id], force: true)
    result = PWN::AI::Agent::Reward.send(:annotate_session, session_id: session[:id], rewards: [1], binding: snapshot[:binding])
    expect(result).to include(annotated: true, binding_sha256: Digest::SHA256.hexdigest(JSON.generate(snapshot[:binding])))
    expect(PWN::Sessions.load(session_id: session[:id]).select { |row| row[:role] == 'tool' }.map { |row| row[:step_reward] }).to eq([1, nil])
    expect(described_class.evidence_transcript(row: original_row).select { |row| row[:role] == 'tool' }.map { |row| row[:step_reward] }).to eq([nil, nil])
  end

  it 'rejects a stale archived PRM binding before any index or snapshot publication' do
    session = PWN::Sessions.create
    PWN::Sessions.append(session_id: session[:id], role: 'user', content: 'request')
    PWN::Sessions.append(session_id: session[:id], role: 'tool', content: 'tool')
    binding = PWN::AI::Agent::Reward.prm_snapshot(session_id: session[:id], request: 'request')[:binding].merge(prefix_sha256: 'f' * 64)
    described_class.note_outcome(task: 'retained evidence', success: false, session_id: session[:id])
    described_class.migrate_evidence(dry_run: false)
    PWN::Sessions.delete(session_id: session[:id], force: true)
    before = File.binread(described_class::LEARNING_FILE)
    result = described_class.annotate_evidence(session_id: session[:id], rewards: [1], binding: binding)
    expect(result).to include(annotated: false, reason: :stale_binding)
    expect(File.binread(described_class::LEARNING_FILE)).to eq(before)
  end

  it 'preserves opaque manual identifiers without inventing a source transcript' do
    row = described_class.note_outcome(task: 'manual assessment', session_id: 'sess-p20-hi', success: false)
    expect(row[:session_id]).to eq('sess-p20-hi')
    expect(File).not_to exist(File.join(PWN::Sessions::SESSIONS_DIR, 'sess-p20-hi.jsonl'))
    expect(described_class.outcomes.first[:session_id]).to eq('sess-p20-hi')
  end

  it 'binds a new canonical outcome to verified archived evidence after source deletion' do
    session = PWN::Sessions.create
    described_class.note_outcome(task: 'initial assessment', session_id: session[:id], success: false)
    described_class.migrate_evidence(dry_run: false)
    expected = described_class.session_evidence(session_id: session[:id])
    PWN::Sessions.delete(session_id: session[:id], force: true)
    row = described_class.note_outcome(task: 'offline reassessment', session_id: session[:id], success: false)
    expect(described_class.evidence_transcript(row: row)).to eq(expected)
    expect(described_class.evidence_complete?(row: row)).to be(true)
  end

  it 'rejects missing canonical evidence without publishing a dangling reference' do
    expect { described_class.note_outcome(task: 'missing source', session_id: '20000101_000000_aabbccdd', success: false) }.to raise_error(IOError)
    expect(described_class.outcomes).to eq([])
  end
end
