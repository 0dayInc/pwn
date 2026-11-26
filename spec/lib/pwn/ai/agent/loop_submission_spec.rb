# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Loop, 'submission accounting' do
  include_context 'pwn tmp sandbox'

  let(:policy) { PWN::AI::Agent::Policy }
  let(:learning) { PWN::AI::Agent::Learning }
  let(:submissions) { PWN::AI::Agent::Submission }
  let(:sid) { PWN::Sessions.create(title: 'fixture')[:id] }
  let(:request) { 'What color is a lemon?' }

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    allow(described_class).to receive(:should_auto_introspect?).and_return(false)
    @agent_cfg[:plan_first] = false
  end

  def deny_plan
    require 'rest-client'
    @agent_cfg[:plan_first] = true
    response = Struct.new(:code, :body).new(403, 'private reason')
    expect(PWN::AI::Grok).to receive(:chat_with_tools).once.and_raise(RestClient::Forbidden.new(response))
    expect(PWN::AI::Agent::Dispatch).not_to receive(:call)
  end

  it 'counts a denied planner once with unknown truth and releases its unscored episode' do
    deny_plan
    expect(policy).not_to receive(:update_q!)
    expect(policy).not_to receive(:update_pg!)
    row = nil
    described_class.run(request: 'Save a meeting agenda to ./agenda.txt.', session_id: sid, engine: :grok,
                        system_role_content: 'fixture', on_outcome: ->(outcome) { row = outcome })
    expect(policy.current_episode).to be_nil
    expect(policy.trajectories).to contain_exactly(hash_including(score: nil, return: nil, episode_role: 'top_level', close_role: 'controller', submission_id: row.fetch(:submission_id)))
    expect(row).to include(status: 'blocked', stage: 'planning', delivery: 'unknown', adjudication: 'unknown')
    expect(learning.stats[:submissions]).to include(total: 1, unknown: 1, false_blocks: 0, false_completions: 0, false_block_rate: nil, false_completion_rate: nil)
  end

  it 'uses the explicit native checker without enabling a learning judge' do
    expect(PWN::AI::Agent::Reward).not_to receive(:judge)
    expect(PWN::AI::Agent::Verification).to receive(:run).once.and_call_original
    allow(described_class).to receive(:call_engine).and_return(role: 'assistant', content: 'Yellow.')
    row = nil
    id = submissions.open!
    described_class.run(request: request, session_id: sid, submission_id: id, system_role_content: 'fixture',
                        verification_contract: { root: @tmp, requirements: [request], checks: [{ kind: :answer, requirement: request, expected: 'Yellow.' }] },
                        on_outcome: ->(outcome) { row = outcome })
    expect(row).to include(submission_id: id, adjudication: 'pass', goal_status: 'complete', delivery: 'unknown')
    expect(submissions.stats).to include(total: 1, unknown: 0, checked_completions: 1, false_completions: 0)
    expect { described_class.run(submission_id: id, request: 'hi') }.to raise_error(ArgumentError, /unavailable/)
    expect(submissions.stats[:total]).to eq(1)
  end

  it 'keeps a main provider access denial distinct from an admission failure, a planner denial, and a bad answer' do
    require 'rest-client'
    denied = RestClient::Forbidden.new(Struct.new(:code, :body).new(403, 'synthetic provider detail'))
    expect(described_class).not_to receive(:plan_first)
    expect(PWN::AI::Grok).to receive(:chat_with_tools).once.and_raise(denied)
    expect(PWN::AI::Agent::Reward).not_to receive(:judge)
    row = nil
    expect do
      described_class.run(request: 'Draft a thank-you note.', session_id: sid, engine: :grok, on_outcome: ->(result) { row = result })
    end.to(raise_error(RestClient::Forbidden) { |error| expect(error).to equal(denied) })
    expect(row).to include(status: 'blocked', stage: 'provider', adjudication: 'unknown', delivery: 'unknown')
    expect(submissions.stats).to include(total: 1, unknown: 1, by_stage: { 'provider' => 1 })
    expect(policy.trajectories).to contain_exactly(hash_including(score: nil, return: nil, submission_id: row[:submission_id]))
  end

  it 'measures real blocked and completed controller decisions against independent post-turn checks' do
    path = File.join(@tmp, 'note.txt')
    File.write(path, 'expected bytes')
    goal = "Ensure #{path} contains exactly expected bytes."
    blocked = nil
    deny_plan
    described_class.run(request: goal, session_id: sid, engine: :grok, system_role_content: 'fixture', on_outcome: ->(row) { blocked = row })
    expect(blocked).to include(status: 'blocked', adjudication: 'unknown')
    verifier = PWN::AI::Agent::Verification
    file_report = verifier.run(request: goal, root: @tmp, requirements: [goal], checks: [{ requirement: goal, kind: :file, expected: 'expected bytes', path: path }])
    submissions.adjudicate!(submission_id: blocked[:submission_id], report: file_report.merge(submission_id: blocked[:submission_id]))

    completed = nil
    expect(described_class).not_to receive(:plan_first)
    expect(described_class).to receive(:call_engine).once.and_return(role: 'assistant', content: 'Blue.')
    answer = described_class.run(request: request, session_id: PWN::Sessions.create(title: 'public question')[:id], system_role_content: 'fixture', on_outcome: ->(row) { completed = row })
    expect(completed).to include(status: 'complete', adjudication: 'unknown')
    report = verifier.run(request: request, root: @tmp, requirements: [request], checks: [{ requirement: request, kind: :answer, expected: 'Yellow.' }], answer: answer)
    2.times { submissions.adjudicate!(submission_id: completed[:submission_id], report: report.merge(submission_id: completed[:submission_id])) }
    expect(submissions.stats).to include(total: 2, unknown: 0, checked_blocks: 1, checked_completions: 1, false_blocks: 1, false_completions: 1)
    expect { submissions.adjudicate!(submission_id: blocked[:submission_id], report: report.merge(submission_id: completed[:submission_id])) }.to raise_error(ArgumentError)
    expect { submissions.adjudicate!(submission_id: blocked[:submission_id], report: report.merge(submission_id: blocked[:submission_id])) }.to raise_error(ArgumentError)
    expect(policy.trajectories.map { |row| row[:score] }).to all(be_nil)
  end

  it 'preserves the outer episode and counts a child with the same request identity only as a nested trajectory' do
    options = { request: request, request_id: 'shared-fixture-id', force_tools: true, system_role_content: 'fixture', enabled_toolsets: [] }
    allow(described_class).to receive(:call_engine) do
      owner = policy.current_episode
      if owner[:session_id] == sid
        expect(described_class.run(options.merge(session_id: 'inner', nested: true))).to eq('Yellow.')
        expect(policy.current_episode).to equal(owner)
      end
      { role: 'assistant', content: 'Yellow.' }
    end
    row = nil
    expect(described_class.run(options.merge(session_id: sid, on_outcome: ->(r) { row = r }))).to eq('Yellow.')
    expect(submissions.stats).to include(total: 1, unknown: 1)
    expect(policy.trajectories.map { |t| t.values_at(:episode_role, :close_role, :submission_id, :score) }).to contain_exactly(
      ['nested', 'controller', row.fetch(:submission_id), nil], ['top_level', 'controller', row.fetch(:submission_id), nil]
    )
    expect(policy.current_episode).to be_nil
  end

  it 'closes the steered segment without a score and keeps one submission across the restart' do
    steering = described_class::Steering.new(input: StringIO.new, output: StringIO.new)
    steering.submit('Please use one word.')
    expect(described_class).to receive(:call_engine).once.and_return(role: 'assistant', content: 'Yellow.')
    row = nil
    described_class.run(request: request, session_id: sid, steering: steering, enabled_toolsets: [], force_tools: true, system_role_content: 'fixture', on_outcome: ->(r) { row = r })
    expect(submissions.stats).to include(total: 1, unknown: 1)
    expect(policy.trajectories.map { |t| t.values_at(:close_role, :submission_id, :score) }).to contain_exactly(
      ['steering', row.fetch(:submission_id), nil], ['controller', row.fetch(:submission_id), nil]
    )
    expect(row.fetch(:request_digest)).to eq(Digest::SHA256.hexdigest("#{request}\nPlease use one word."))
  end

  it 'closes a detached episode exactly once in the deferred reviewer without submitting its internal turn' do
    finalizer = PWN::AI::Agent::TurnFinalizer
    allow(described_class).to receive(:should_auto_introspect?).and_return(true)
    @agent_cfg[:auto_introspect] = true
    allow(learning).to receive(:auto_introspect).and_wrap_original do |method, opts|
      if opts[:inline]
        parent = policy.current_episode
        described_class.run(request: request, session_id: 'review-child', force_tools: true, system_role_content: 'fixture', enabled_toolsets: [])
        expect(policy.current_episode).to equal(parent)
        raise IOError, 'optional review failed before assigning a score'
      end
      method.call(opts)
    end
    allow(described_class).to receive(:call_engine).and_return(role: 'assistant', content: 'Yellow.')
    row = nil
    expect(described_class.run(request: request, session_id: sid, force_tools: true, system_role_content: 'fixture', on_outcome: ->(r) { row = r })).to eq('Yellow.')
    finalizer.join_all!(timeout: 5)
    expect(submissions.stats[:total]).to eq(1)
    expect(policy.trajectories.map { |t| t.values_at(:episode_role, :close_role, :submission_id, :score) }).to contain_exactly(
      ['top_level', 'deferred', row.fetch(:submission_id), nil], ['nested', 'controller', row.fetch(:submission_id), nil]
    )
    expect(policy.current_episode).to be_nil
  ensure
    finalizer&.join_all!(timeout: 5)
  end

  it 'does not substitute optional open or claim errors for an ordinary answer' do
    opts = { request: 'hi', session_id: sid, system_role_content: 'fixture' }
    allow(described_class).to receive(:answer_greeting).and_return('Hello.')
    expect(submissions).to receive(:open!).once.and_raise(Errno::EACCES)
    expect(described_class.run(opts)).to eq('Hello.')
    expect(submissions).to receive(:claim!).once.and_raise(Errno::EROFS)
    expect(described_class.run(opts.merge(submission_id: 'a' * 32))).to eq('Hello.')
  end

  it 'does not hang a request behind a stalled optional receipt reader or writer' do
    submissions.open!
    lock_path = File.join(PWN::Sessions.sessions_dir, 'support', 'submissions', '.lock')
    allow(described_class).to receive(:answer_greeting).and_return('Hello.')
    File.open(lock_path, File::RDWR) do |lock|
      lock.flock(File::LOCK_EX)
      answer = Timeout.timeout(2) { described_class.run(request: 'hi', session_id: sid, system_role_content: 'fixture') }
      expect(answer).to eq('Hello.')
    end
  end

  it 'isolates a denied receipt store but never swallows the actual request security error' do
    opts = { request: 'hi', session_id: sid, system_role_content: 'fixture' }
    allow(submissions).to receive(:open!).and_raise(SecurityError, 'receipt store denied')
    allow(described_class).to receive(:answer_greeting).and_return('Hello.')
    expect(described_class.run(opts)).to eq('Hello.')
    allow(described_class).to receive(:answer_greeting).and_raise(SecurityError, 'request denied')
    expect { described_class.run(opts.merge(on_outcome: ->(_r) { raise IOError, 'observer failed' })) }.to raise_error(SecurityError, 'request denied')
  end

  it 'does not substitute an optional close error for an answer, an admission error, or an interrupt' do
    opts = { request: 'hi', session_id: sid, system_role_content: 'fixture' }
    allow(described_class).to receive(:answer_greeting).and_return('Hello.')
    allow(submissions).to receive(:close!).and_raise(IOError, 'accounting unavailable')
    row = nil
    expect(described_class.run(opts.merge(on_outcome: ->(r) { row = r }))).to eq('Hello.')
    expect(row).to include(status: 'complete')
    expect { described_class.run(opts.merge(request: 'continue', require_resumable: true)) }.to raise_error(ArgumentError, /no longer has an unfinished request/)
    allow(described_class).to receive(:answer_greeting).and_raise(Interrupt, 'original interrupt')
    expect { described_class.run(opts) }.to raise_error(Interrupt, 'original interrupt')
  end

  it 'keeps an admission failure primary even if the new outcome observer also fails' do
    opts = { request: 'continue', session_id: sid, require_resumable: true, on_outcome: ->(_row) { raise IOError, 'observer unavailable' } }
    expect { described_class.run(opts) }.to raise_error(ArgumentError, /no longer has an unfinished request/)
    expect(submissions.stats).to include(total: 1, by_status: { 'blocked' => 1 }, by_stage: { 'admission' => 1 }, unknown: 1)
  end

  it 'records an actual account refusal as admission, not finalization or a measured false block' do
    @agent_cfg[:operator_account] = 'owner'
    expect(described_class).not_to receive(:call_engine)
    row = nil
    expect(described_class.run(request: request, session_id: sid, from: 'other', on_outcome: ->(r) { row = r })).to include('Refused')
    expect(row).to include(status: 'blocked', stage: 'admission', adjudication: 'unknown')
    expect(submissions.stats).to include(total: 1, unknown: 1, checked_blocks: 0)
  end

  it 'persists an unscored standalone close without writing the policy table' do
    policy.begin_episode(session_id: sid, request: request)
    expect(policy.finish(score: nil)).to include(td_updates: 0, pg_updates: 0, score: nil, return: nil)
    expect(File.exist?(policy::POLICY_FILE)).to be(false)
    expect(File.stat(policy::TRAJECTORY_FILE).mode & 0o777).to eq(0o600)
    expect(policy.trajectories).to contain_exactly(hash_including(submission_id: nil, episode_role: 'standalone', close_role: 'direct'))
  end

  it 'keeps correlation metadata private when appending to or compacting legacy trajectories' do
    path = policy::TRAJECTORY_FILE
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, '')
    File.chmod(0o644, path)
    policy.begin_episode(session_id: sid, request: request)
    expect(policy.finish(score: nil)).to include(score: nil)
    expect(File.stat(path).mode & 0o077).to eq(0)
    expect(policy.lean!).to include(remaining: 1)
    expect(File.stat(path).mode & 0o077).to eq(0)
    expect(policy.trajectories).to contain_exactly(hash_including(close_role: 'direct', score: nil))
  end

  it 'retains the submission identity for a deferred child started after the parent episode closes' do
    finalizer = PWN::AI::Agent::TurnFinalizer
    allow(described_class).to receive(:should_auto_introspect?).and_return(true)
    @agent_cfg[:auto_introspect] = true
    allow(learning).to receive(:auto_introspect).and_wrap_original do |method, opts|
      if opts[:inline]
        policy.finish(score: nil)
        described_class.run(request: request, session_id: 'late-child', force_tools: true, system_role_content: 'fixture', enabled_toolsets: [])
      else
        method.call(opts)
      end
    end
    allow(described_class).to receive(:call_engine).and_return(role: 'assistant', content: 'Yellow.')
    row = nil
    described_class.run(request: request, session_id: sid, force_tools: true, system_role_content: 'fixture', on_outcome: ->(r) { row = r })
    finalizer.join_all!(timeout: 5)
    expect(policy.trajectories.map { |t| t.values_at(:episode_role, :submission_id) }).to contain_exactly(['top_level', row[:submission_id]], ['nested', row[:submission_id]])
    expect(submissions.stats[:total]).to eq(1)
  ensure
    finalizer&.join_all!(timeout: 5)
  end

  [false, true].each do |deferred|
    it "records the actual #{deferred ? 'deferred' : 'inline'} learning closer, independent of its nil score" do
      finalizer = PWN::AI::Agent::TurnFinalizer
      allow(described_class).to receive(:should_auto_introspect?).and_return(true)
      @agent_cfg.merge!(auto_introspect: true, defer_introspect: deferred)
      allow(PWN::AI::Agent::Reward).to receive(:judge).and_return(score: nil, source: :error)
      allow(PWN::AI::Agent::Curriculum).to receive(:critic).and_return(verdict: :pass)
      allow(learning).to receive(:should_gc_stores?).and_return(false)
      allow(described_class).to receive(:call_engine).and_return(role: 'assistant', content: 'Yellow.')
      row = nil
      expect(described_class.run(request: request, force_tools: true, session_id: sid, system_role_content: 'fixture', on_outcome: ->(r) { row = r })).to eq('Yellow.')
      finalizer.join_all!(timeout: 5)
      expect(policy.trajectories).to contain_exactly(hash_including(close_role: deferred ? 'deferred' : 'learning', submission_id: row[:submission_id], score: nil, return: nil))
      expect(submissions.stats).to include(total: 1, unknown: 1)
    ensure
      finalizer&.join_all!(timeout: 5)
    end
  end
end
