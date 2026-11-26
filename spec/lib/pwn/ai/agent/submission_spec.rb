# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Submission do
  include_context 'pwn tmp sandbox'

  it 'documents the controller-only receipt API' do
    expect(described_class.authors).to include('AUTHOR(S)')
    expect { described_class.help }.to output(/open!.*claim!.*abandon!.*close!.*delivery!.*adjudicate!.*stats/m).to_stdout
  end

  it 'writes only fixed metadata in private files and rejects content in correlation fields' do
    expect { described_class.open!(claimed: 'private candidate') }.to raise_error(ArgumentError)
    id = described_class.open!(claimed: true)
    root = File.join(PWN::Sessions.sessions_dir, 'support', 'submissions')
    path = File.join(root, id)
    expect(File.stat(root).mode & 0o777).to eq(0o700)
    expect(File.stat(path).mode & 0o777).to eq(0o600)
    expect(File.stat(File.join(root, '.lock')).mode & 0o777).to eq(0o600)
    outcome = { status: :incomplete, unmet: ['private verifier detail'], request_id: 'private identity', answer: 'private candidate' }
    expect { described_class.close!(submission_id: id, outcome: outcome, request_key: 'private identity') }.to raise_error(ArgumentError)
    expect { described_class.close!(submission_id: id, outcome: outcome, request_digest: 'private request') }.to raise_error(ArgumentError)
    described_class.close!(submission_id: id, outcome: outcome)
    expect(File.read(path)).not_to include('private')
  end

  it 'claims a reserved parent receipt once and never overwrites an existing close or delivery' do
    id = described_class.open!
    expect(described_class.claim!(submission_id: id)).to eq(id)
    expect { described_class.claim!(submission_id: id) }.to raise_error(ArgumentError)
    expect { described_class.claim!(submission_id: '../elsewhere') }.to raise_error(ArgumentError)
    described_class.close!(submission_id: id, outcome: { status: 'complete', stage: 'finalization' })
    expect(described_class.abandon!(submission_id: id, status: :cancelled, stage: :cancellation)).to include(status: 'complete')
    2.times { described_class.delivery!(submission_id: id, delivery: :displayed) }
    expect { described_class.delivery!(submission_id: id, delivery: :not_displayed) }.to raise_error(ArgumentError)
    expect(described_class.stats).to include(total: 1, unknown: 1, by_delivery: { 'displayed' => 1 })
  end

  it 'recovers a pending reservation without manufacturing a checker or displaying a reply' do
    id = described_class.open!
    expect(described_class.abandon!(submission_id: id, status: :cancelled, stage: :cancellation)).to include(claimed: false, goal_status: 'cancelled', delivery: 'unknown', adjudication: 'unknown')
    expect { described_class.claim!(submission_id: id) }.to raise_error(ArgumentError, /unavailable/)
    described_class.delivery!(submission_id: id, delivery: :not_displayed)
    expect(described_class.stats).to include(total: 1, unknown: 1, by_delivery: { 'not_displayed' => 1 })
  end

  it 'keeps unchecked truth unknown and rejects verdict-only or contradictory labels' do
    id = described_class.open!(claimed: true)
    request = 'First. Second.'
    digest = Digest::SHA256.hexdigest(request)
    described_class.close!(submission_id: id, outcome: { status: :complete }, request_digest: digest)
    report = PWN::AI::Agent::Verification.run(request: request, root: @tmp, requirements: %w[First Second],
                                              checks: [{ kind: :answer, requirement: 'First', expected: 'One.' }], answer: 'One.').merge(submission_id: id)
    expect(described_class.adjudicate!(submission_id: id, report: report)).to include(adjudication: 'unknown')
    expect { described_class.adjudicate!(submission_id: id, verdict: :fail) }.to raise_error(ArgumentError)
    expect { described_class.adjudicate!(submission_id: id, report: report.merge(status: :pass)) }.to raise_error(ArgumentError)
    expect(described_class.stats).to include(unknown: 1, checked_completions: 0, false_completion_rate: nil)
  end

  it 'treats a nonprivate or invalid record as unreadable instead of publishing its contents' do
    id = described_class.open!(claimed: true)
    root = File.join(PWN::Sessions.sessions_dir, 'support', 'submissions')
    path = File.join(root, id)
    data = JSON.parse(File.read(path)).merge('private' => 'not a receipt field')
    File.write(path, JSON.generate(data))
    expect(described_class.stats).to include(total: 1, unreadable: 1, unknown: 1, by_status: {})
    File.chmod(0o644, path)
    expect { described_class.delivery!(submission_id: id, delivery: :displayed) }.to raise_error(IOError)
    expect(File.stat(path).mode & 0o777).to eq(0o644)
  end

  it 'does not scan submissions for prompt context or let a reporting failure break existing learning statistics' do
    learning = PWN::AI::Agent::Learning
    learning.note_outcome(task: 'test note', success: true, score: 0.9)
    allow(described_class).to receive(:stats).and_raise(Errno::EACCES)
    expect(learning.to_context).to include('RECENT OUTCOMES')
    expect(described_class).not_to have_received(:stats)
    expect(learning.stats).to include(total_outcomes: 1, submissions: nil)
  end
end
