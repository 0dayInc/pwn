# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Agent::Curriculum do
  include_context 'pwn tmp sandbox'

  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Curriculum
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Curriculum
    expect(help_response).to respond_to :help
  end

  it 'calibrate computes brier and records to Metrics' do
    stub_const('PWN::AI::Agent::Metrics::METRICS_FILE', File.join(Dir.mktmpdir, 'm.json'))
    r = described_class.calibrate(predicted: 0.8, actual: 1.0, engine: :ollama)
    expect(r[:brier]).to eq 0.04
    cal = PWN::AI::Agent::Metrics.calibration(engine: :ollama)
    expect(cal[:n]).to eq 1
  end

  it 'practice dry_run generates reproducers without self-play' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(tmp, 'mistakes.json'))
    stub_const('PWN::AI::Agent::Curriculum::CURRICULUM_DIR', File.join(tmp, 'curr'))
    PWN::AI::Agent::Mistakes.record(tool: 'shell', error: 'nmpa: command not found')
    r = described_class.practice(limit: 1, dry_run: true)
    expect(r[:dry_run]).to be true
    expect(r[:practiced]).to eq 1
    expect(r[:results].first[:prompts]).not_to be_empty
  end

  it 'train_and_gate dry_run exports datasets and manual CLI' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(tmp, 'l.jsonl'))
    stub_const('PWN::AI::Agent::Learning::FINETUNE_DIR', tmp)
    stub_const('PWN::AI::Agent::Reward::PREFERENCES_FILE', File.join(tmp, 'p.jsonl'))
    stub_const('PWN::AI::Agent::Reward::DPO_DIR', tmp)
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(tmp, 'm.json'))
    stub_const('PWN::AI::Agent::Curriculum::CURRICULUM_DIR', File.join(tmp, 'c'))
    stub_const('PWN::AI::Agent::Curriculum::MODELS_FILE', File.join(tmp, 'c', 'models.json'))

    r = described_class.train_and_gate(dry_run: true)
    expect(r[:dry_run]).to be true
    expect(r[:manual_cli]).to be_an(Array)
    expect(r[:version]).to eq 1
  end

  describe '.offline_judge' do
    let(:reward) { PWN::AI::Agent::Reward }
    let(:learning) { PWN::AI::Agent::Learning }
    let(:outcome) do
      reward.resolve_outcome(outcome: { score: 0.95, source: :heuristic, confidence: 0.35, rationale: 'overlap only' })
    end

    before do
      allow(PWN::Sessions).to receive(:list).and_return([{ id: 'curriculum-test' }])
      allow(PWN::Sessions).to receive(:load).and_return([
                                                          { role: 'user', content: 'check the result' },
                                                          { role: 'assistant', content: 'PLAN: check result p(success)=0.8' },
                                                          { role: 'assistant', content: 'result checked' }
                                                        ])
      allow(learning).to receive(:outcomes).and_return([])
      allow(learning).to receive(:note_outcome)
      allow(reward).to receive(:judge).and_return(outcome)
      allow(reward).to receive(:prm)
      allow(reward).to receive(:warm_sentinel)
      allow(reward).to receive(:scrub_preferences)
      allow(reward).to receive(:generator_mix)
      allow(described_class).to receive(:calibrate)
      allow(described_class).to receive(:reclassify_backlog).and_return({ reclassified: 0 })
      allow(described_class).to receive(:practice_kpi)
      allow(described_class).to receive(:log)
    end

    it 'preserves unknown outcomes without PRM or calibration training' do
      result = described_class.offline_judge

      expect(reward).not_to have_received(:prm)
      expect(described_class).not_to have_received(:calibrate)
      expect(learning).to have_received(:note_outcome).with(hash_including(outcome: outcome, tags: %w[offline_judge auto unknown]))
      expect(result[:results].first).to include(outcome)
    end

    it 'retries previously unknown outcomes instead of treating their diagnostic scores as labels' do
      allow(learning).to receive(:outcomes).and_return([outcome.merge(session_id: 'curriculum-test', tags: ['offline_judge'])])

      result = described_class.offline_judge

      expect(result[:scored]).to eq(1)
      expect(reward).to have_received(:judge)
    end

    it 'persists unknown verdict and confidence in the real learning ledger' do
      stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(Dir.mktmpdir, 'learning.jsonl'))
      allow(learning).to receive(:note_outcome).and_call_original
      allow(learning).to receive(:outcomes).and_call_original

      described_class.offline_judge

      expect(learning.outcomes.first).to include(
        verdict: 'unknown', confidence: 0.35, training_score: nil,
        decision_version: 1, status: 'unverified'
      )
    end

    context 'with an error outcome' do
      let(:outcome) { reward.resolve_outcome(outcome: { source: :error, error: 'judge unavailable' }) }

      it 'keeps missing scores unknown without training a failure label' do
        result = described_class.offline_judge

        expect(result[:results].first).to include(outcome)
        expect(reward).not_to have_received(:prm)
        expect(described_class).not_to have_received(:calibrate)
        expect(learning).to have_received(:note_outcome).with(hash_including(outcome: outcome))
      end
    end

    context 'with a known failure' do
      let(:outcome) { reward.resolve_outcome(outcome: { score: 0.4, source: :llm_orm }) }

      it 'calibrates partial credit against failure rather than a fractional success label' do
        described_class.offline_judge

        expect(described_class).to have_received(:calibrate).with(hash_including(actual: 0.0))
        expect(reward).to have_received(:prm)
        expect(learning).to have_received(:note_outcome).with(hash_including(outcome: outcome, tags: %w[offline_judge auto partial]))
      end
    end

    context 'with a known outcome' do
      let(:outcome) { reward.resolve_outcome(outcome: { score: 0.65, source: :llm_orm, confidence: 0.85 }) }

      it 'calibrates predicted success against the resolved label, not the diagnostic score' do
        described_class.offline_judge

        expect(described_class).to have_received(:calibrate).with(hash_including(predicted: 0.8, actual: 1.0))
        expect(reward).to have_received(:prm)
        expect(learning).to have_received(:note_outcome).with(hash_including(outcome: outcome))
      end

      it 'does not annotate or train sessions when commit is false' do
        described_class.offline_judge(commit: false)

        expect(reward).not_to have_received(:prm)
        expect(learning).not_to have_received(:note_outcome)
        expect(described_class).not_to have_received(:calibrate)
      end
    end
  end

  describe 'practice reward decisions' do
    let(:reward) { PWN::AI::Agent::Reward }
    let(:outcome) { reward.resolve_outcome(outcome: { score: 0.95, source: :heuristic, confidence: 0.35 }) }

    before do
      allow(PWN::Sessions).to receive(:create).and_return({ id: 'practice-test' })
      allow(PWN::Sessions).to receive(:load).and_return([{ role: 'tool', content: 'shell: checked result with a real tool trace' }])
      allow(PWN::AI::Agent::Loop).to receive(:run).and_return('candidate answer')
      allow(reward).to receive(:judge).and_return(outcome)
    end

    it 'keeps the entire resolved outcome on self-play trials' do
      run = described_class.send(:self_play, prompt: 'check result', tag: 'test')

      expect(run).to include(outcome)
      expect(run).to include(final: 'candidate answer', session_id: 'practice-test')
      expect(run[:trace]).to include('shell: checked result')
    end

    it 'retains failed trial context with an unknown decision when judging errors' do
      allow(reward).to receive(:judge).and_raise(StandardError, 'judge unavailable')

      run = described_class.send(:self_play, prompt: 'check result', tag: 'test')

      expect(run).to include(
        session_id: 'practice-test', final: 'candidate answer', prompt: 'check result',
        source: :error, verdict: :unknown, success: nil, training_score: nil,
        decision_version: 1, error: 'judge unavailable'
      )
    end

    context 'when replaying model evaluations' do
      let(:failed) { reward.resolve_outcome(outcome: { score: 0.2, source: :llm_orm }) }
      let(:solved) { reward.resolve_outcome(outcome: { score: 0.65, source: :llm_orm }) }
      let(:evalset) { [{ prompt: 'unknown check' }, { prompt: 'failed check' }, { prompt: 'solved check' }] }

      before do
        allow(reward).to receive(:judge).and_return(outcome, failed, solved)
      end

      it 'counts canonical successes and excludes unknown scores from the evaluation mean' do
        result = described_class.send(:replay_on_detailed, tag: 'test-model', evalset: evalset)

        expect(result[:resolved]).to eq(1)
        expect(result[:mean_score]).to eq(0.425)
        expect(result[:unknown]).to eq(1)
        expect(result[:outcomes]).to match([include(outcome), include(failed), include(solved)])
      end

      it 'uses the same trusted decision for legacy replay counts' do
        expect(described_class.send(:replay_on, tag: 'test-model', evalset: evalset.first(2))).to eq(0)
        expect(described_class.send(:replay_on, tag: 'test-model', evalset: evalset.last(1))).to eq(1)
      end
    end

    context 'when gating a candidate model' do
      let(:baseline_outcome) { outcome }
      let(:candidate_outcome) { reward.resolve_outcome(outcome: { score: 0.65, source: :llm_orm }) }

      before do
        allow(described_class).to receive(:self_play) do |opts|
          opts[:tag] == 'gate:baseline' ? baseline_outcome : candidate_outcome
        end
      end

      it 'refuses promotion when a comparison contains unknown outcomes' do
        result = described_class.send(:ab_gate_v2, baseline: 'baseline', candidate: 'candidate', evalset: [{ prompt: 'check' }])

        expect(result[:promote]).to be(false)
        expect(result[:outcomes_known]).to be(false)
      end

      context 'with all outcomes known' do
        let(:baseline_outcome) { reward.resolve_outcome(outcome: { score: 0.2, source: :llm_orm }) }

        it 'can promote a trusted improvement over known failures' do
          result = described_class.send(:ab_gate_v2, baseline: 'baseline', candidate: 'candidate', evalset: [{ prompt: 'check' }])

          expect(result[:promote]).to be(true)
          expect(result[:outcomes_known]).to be(true)
        end
      end
    end

    context 'when practising a mistake' do
      before do
        stub_const('PWN::AI::Agent::Curriculum::CURRICULUM_DIR', Dir.mktmpdir)
        allow(PWN::AI::Agent::Mistakes).to receive(:top).and_return([{ signature: 'test', tool: 'shell', count: 3 }])
        allow(PWN::AI::Agent::Mistakes).to receive(:resolve)
        allow(PWN::AI::Agent::Mistakes).to receive(:operator_inbox).and_return({ count: 0, items: [] })
        allow(reward).to receive(:record_preference)
        allow(reward).to receive(:generator_mix)
        allow(described_class).to receive(:generate_reproducers).and_return(['first check', 'second check'])
        allow(described_class).to receive(:load_cooldown).and_return({})
        allow(described_class).to receive(:save_cooldown)
        allow(described_class).to receive(:practice_kpi)
        allow(described_class).to receive(:log)
      end

      it 'does not resolve or create winning trajectories from high-scoring unknowns' do
        cooldown = { 'test' => { 'fail_nights' => 1 } }
        allow(described_class).to receive(:load_cooldown).and_return(cooldown)
        result = described_class.practice(limit: 1)

        expect(result[:resolved]).to eq(0)
        expect(cooldown).to eq('test' => { 'fail_nights' => 1 })
        expect(result[:results].first[:mean_score]).to be_nil
        expect(PWN::AI::Agent::Mistakes).not_to have_received(:resolve)
        expect(reward).not_to have_received(:record_preference)
        expect(result[:results].first[:runs]).to all(include(outcome))
      end

      context 'when the evaluator errors' do
        it 'leaves failure cooldown unchanged rather than parking an unknown-only practice night' do
          cooldown = { 'test' => { 'fail_nights' => 2, 'last_mean' => 0.1 } }
          original = Marshal.load(Marshal.dump(cooldown))
          allow(described_class).to receive(:load_cooldown).and_return(cooldown)
          allow(reward).to receive(:judge).and_raise(StandardError, 'judge unavailable')
          allow(PWN::AI::Agent::Mistakes).to receive(:park)

          result = described_class.practice(limit: 1)

          expect(cooldown).to eq(original)
          expect(result[:results].first).to include(resolved: false, mean_score: nil)
          expect(described_class).to have_received(:save_cooldown).with(cooldown: original)
          expect(PWN::AI::Agent::Mistakes).not_to have_received(:park)
        end
      end

      it 'still parks repeated verified failures without letting unknown scores mask them' do
        failed = reward.resolve_outcome(outcome: {
                                          score: 0.0, source: :heuristic,
                                          verification: { checks: [{ criterion: 'required report', passed: false, evidence: 'report absent' }] }
                                        })
        cooldown = {}
        allow(described_class).to receive(:load_cooldown).and_return(cooldown)
        allow(PWN::AI::Agent::Mistakes).to receive(:park)
        allow(described_class).to receive(:self_play).with(hash_including(prompt: 'first check')).and_return(failed)
        allow(described_class).to receive(:self_play).with(hash_including(prompt: 'second check')).and_return(outcome)

        described_class::COOLDOWN_FAIL_NIGHTS.times do
          result = described_class.practice(limit: 1)
          expect(result[:results].first).to include(resolved: false, mean_score: 0.0)
        end

        expect(cooldown['test']).to include('fail_nights' => described_class::COOLDOWN_FAIL_NIGHTS, 'parked' => true)
        expect(PWN::AI::Agent::Mistakes).to have_received(:park).with(hash_including(signature: 'test'))
      end

      context 'with trusted success' do
        let(:outcome) { reward.resolve_outcome(outcome: { score: 0.65, source: :llm_orm, confidence: 0.85 }) }

        it 'resolves holdouts from the canonical success decision' do
          result = described_class.practice(limit: 1)

          expect(result[:resolved]).to eq(1)
          expect(PWN::AI::Agent::Mistakes).to have_received(:resolve)
          expect(reward).to have_received(:record_preference)
        end
      end
    end
  end

  it 'critic returns pass when disabled' do
    r = described_class.critic(request: 'x', final: 'y')
    expect(r[:verdict]).to eq :pass
  end
end
