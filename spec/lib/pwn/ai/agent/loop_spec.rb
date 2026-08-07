# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Loop do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Loop
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Loop
    expect(help_response).to respond_to :help
  end

  describe 'RL-adjacent loop contracts' do
    it 'exhaust path still calls task_summary_flush! and auto_introspect' do
      src = File.read(described_class.method(:run).source_location.first)
      # budget exhausted terminal path
      expect(src).to match(/iteration budget exhausted/)
      # after the exhausted final_msg, both flush and auto_introspect must appear
      exhaust = src[/final_msg = '\[pwn-ai\] iteration budget exhausted'.*/m]
      expect(exhaust).to match(/Learning\.auto_introspect/)
      expect(exhaust).to match(/task_summary_flush!/)
      # flush before return of final_msg
      expect(exhaust).to match(/task_summary_flush!.*final_msg/m)
    end

    it 'plan_first unifies ts_state plan after red_team (P2)' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/TaskSummarizer\.unify_plan!/)
      expect(src).to match(/ts_state: ts_state/)
      expect(src).to match(/red_team_plan/)
    end

    it 'auto_introspect receives plan from ts_state on success and exhaust paths' do
      src = File.read(described_class.method(:run).source_location.first)
      # every auto_introspect in Loop.run should pass plan:
      calls = src.scan(/Learning\.auto_introspect\([^)]*\)/m)
      # also multi-line form collapsed into one-liners already
      expect(calls.length).to be >= 2
      calls.each do |c|
        expect(c).to match(/plan:/), "auto_introspect missing plan: #{c[0, 120]}"
      end
    end

    it 'injects English task focus into model messages (task-as-primary)' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/inject_task_focus!/)
      expect(src).to match(/active_task_prompt/)
      # inject after emit_plan and inside the iteration loop
      expect(src.scan('inject_task_focus!').length).to be >= 3
    end

    it 're-ranks Registry tools from English tangible tasks after plan (sole driver)' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/TaskSummarizer\.relevance_query/)
      expect(src).to match(/relevance_query\(state: ts_state/)
      # Must rebind tools after task_summary_plan! (not only from bare request)
      expect(src).to match(/task_summary_plan!.*relevance_query|relevance_query.*inject_task_focus!/m)
    end

    it 'does not put TaskSummarizer into Reward credit paths' do
      # Loop may call TaskSummarizer executive APIs, not Reward.judge from TaskSummarizer
      ts = File.read(PWN::AI::Agent::TaskSummarizer.method(:plan).source_location.first)
      # TaskSummarizer must not call Reward.judge / Reward.prm / Learning.note_outcome
      expect(ts).not_to match(/Reward\.judge\b/)
      expect(ts).not_to match(/Reward\.prm\b/)
      expect(ts).not_to match(/Learning\.note_outcome\b/)
      # Index pull from R2 is OK via apply_prm_advancement!
      expect(ts).to match(/apply_prm_advancement!/)
    end
  end
end
