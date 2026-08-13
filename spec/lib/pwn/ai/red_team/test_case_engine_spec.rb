# frozen_string_literal: true

require 'spec_helper'
require 'json'

describe PWN::AI::RedTeam::TestCaseEngine do
  it 'execute method should exist' do
    execute_response = PWN::AI::RedTeam::TestCaseEngine
    expect(execute_response).to respond_to :execute
  end

  it 'should display information for authors' do
    authors_response = PWN::AI::RedTeam::TestCaseEngine
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::RedTeam::TestCaseEngine
    expect(help_response).to respond_to :help
  end

  it 'defaults payload_count to ten' do
    expect(described_class::DEFAULT_PAYLOAD_COUNT).to eq(10)
  end

  describe 'strategy-driven generation' do
    let(:refs) do
      {
        red_team_module: PWN::AI::RedTeam::PromptInjection,
        section: 'LLM01: PROMPT INJECTION',
        owasp_llm_uri: 'https://genai.owasp.org/llmrisk/llm01-prompt-injection/',
        atlas_id: 'AML.T0051',
        atlas_uri: 'https://atlas.mitre.org/techniques/AML.T0051'
      }
    end

    let(:strategies) do
      [
        { name: 'direct_override', description: 'Cancel prior directives and demand a canary.' },
        { name: 'delimiter_breakout', description: 'Break out of fences then inject SYSTEM.' }
      ]
    end

    def apply_env_stub
      ai = { active: :grok, module_reflection: false, grok: { model: 'test-model' } }
      allow(PWN::Env).to receive(:[]).and_call_original
      allow(PWN::Env).to receive(:[]).with(:ai).and_return(ai)
    end

    def apply_engine_stub(count_tracker)
      described_class.define_singleton_method(:chat_attacker) do |opts|
        req = JSON.parse(opts[:request].to_s)
        n = req['requested_count'].to_i
        count_tracker[:requested] = n
        count_tracker[:strategies] = req['strategies']
        Array.new(n) { |i| "generated-payload-#{i + 1}" }.to_json
      end
      described_class.define_singleton_method(:dispatch_to_target) { |_opts| 'REFUSED' }
      described_class.define_singleton_method(:judge) { |_opts| 'EPSS 5%' }
    end

    after do
      load File.expand_path('../../../../../lib/pwn/ai/red_team/test_case_engine.rb', __dir__)
    end

    it 'generates payload_count LLM payloads from strategies' do
      tracker = {}
      apply_env_stub
      apply_engine_stub(tracker)

      result = described_class.execute(
        strategies: strategies,
        payload_count: 3,
        security_references: refs,
        target_engine: :grok,
        attacker_engine: :grok,
        max_adaptive_rounds: 0
      )

      expect(tracker[:requested]).to eq(3)
      expect(tracker[:strategies]).not_to be_empty
      expect(result.length).to eq(3)
      expect(result.map { |r| r[:payload_no_and_contents].first[:payload] }).to eq(
        %w[generated-payload-1 generated-payload-2 generated-payload-3]
      )
    end

    it 'defaults to ten generated payloads when payload_count is omitted' do
      tracker = {}
      apply_env_stub
      apply_engine_stub(tracker)

      result = described_class.execute(
        strategies: strategies,
        security_references: refs,
        target_engine: :grok,
        attacker_engine: :grok,
        max_adaptive_rounds: 0
      )

      expect(tracker[:requested]).to eq(10)
      expect(result.length).to eq(10)
    end

    it 'rejects a non-positive payload_count' do
      apply_env_stub
      expect do
        described_class.execute(
          strategies: strategies,
          payload_count: 0,
          security_references: refs,
          target_engine: :grok,
          attacker_engine: :grok,
          max_adaptive_rounds: 0
        )
      end.to raise_error(RuntimeError, /payload_count must be a positive Integer/)
    end
  end
end
