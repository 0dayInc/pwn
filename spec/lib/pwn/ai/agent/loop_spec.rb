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

    it 'P17 evidence_enough does not early-final on bare success while plan open' do
      # Multi-step English plan mid-flight + tool {"success":true} must NOT
      # force text-only — that blocked legitimate completion.
      loop_mod = described_class
      msgs = [
        { role: 'user', content: 'fix p17' },
        { role: 'tool', content: '{"success":true,"result":{"stdout":"a"}}' },
        { role: 'tool', content: '{"success":true,"result":{"stdout":"b"}}' },
        { role: 'tool', content: '{"success":true,"result":{"stdout":"c"}}' }
      ]
      open_plan = { plan: %w[identify determine inspect implement verify confirm], plan_idx: 2 }
      r_open = loop_mod.send(
        :evidence_enough_to_finalize?,
        messages: msgs, turn_fails: {}, i: 5, max_iters: 40,
        request: 'fix p17', plan_steps: 6, ts_state: open_plan
      )
      expect(r_open).to be false

      last_plan = { plan: %w[identify implement verify], plan_idx: 2 }
      msgs_mut = msgs + [
        { role: 'tool', content: '{"success":true,"result":{"stdout":"0 offenses detected"}}' }
      ]
      r_mut = loop_mod.send(
        :evidence_enough_to_finalize?,
        messages: msgs_mut, turn_fails: {}, i: 5, max_iters: 40,
        request: 'fix p17', plan_steps: 3, ts_state: last_plan
      )
      expect(r_mut).to be true

      r_bare = loop_mod.send(
        :evidence_enough_to_finalize?,
        messages: msgs, turn_fails: {}, i: 5, max_iters: 40,
        request: 'fix p17', plan_steps: 3, ts_state: last_plan
      )
      expect(r_bare).to be false

      # call site must pass ts_state
      src = File.read(loop_mod.method(:run).source_location.first)
      expect(src).to match(/evidence_enough_to_finalize\?\([\s\S]*?ts_state: ts_state/)
      expect(src).to match(/English-task gate/)
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

    it 'coerces plain-text tool forms and forces ollama tool_choice when needed' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/tool_calls_from_text/)
      expect(src).to match(/_text_tool_coerced/)
      expect(src).to match(/tool_choice/)
      # stay required while monologue / unfinished; only auto when settled
      expect(src).to match(/still_acting/)
      expect(src).to match(/has_tool_result && !still_acting/)
      # normalize_llm must promote text tool forms
      expect(src).to match(/normalize_llm[\s\S]*tool_calls_from_text/m)
      expect(src).to match(/MONOLOGUE_TOOL_INTENT_RX/)
    end

    it 'flags narrated tool monologue as incomplete_final (ollama gemma thrash)' do
      sample = <<~TXT
        Wait, let's try `hping3 -c 1` with a known IP like `127.0.0.1`.
        If it fails (due to permissions), then we can say "Verification complete".
        Actually, I will just report that the verification failed or we found no hosts.
        Wait, let's try one more thing: check if any way exists a host using hping3.
      TXT
      expect(described_class.send(:incomplete_final?, text: sample, last_iter: false)).to eq(true)
      expect(described_class.send(:incomplete_final?, text: sample, last_iter: true)).to eq(false)
      expect(
        described_class.send(
          :incomplete_final?,
          text: 'Live hosts: 10.3.3.1 via sudo hping3 -1 -c 1 on 10.3.3.0/27.',
          last_iter: false
        )
      ).to eq(false)
    end
  end

  describe '.openai_wire_messages' do
    it 'stringifies Hash function.arguments and drops private keys' do
      wire = described_class.openai_wire_messages(
        messages: [
          {
            role: 'assistant',
            content: nil,
            _text_tool_coerced: true,
            thinking: 'secret',
            tool_calls: [
              {
                id: 'c1',
                type: 'function',
                function: { name: 'shell', arguments: { command: 'id' } }
              }
            ]
          },
          {
            role: 'tool',
            tool_call_id: 'c1',
            name: 'shell',
            content: { success: true, result: 'uid=0' }
          }
        ]
      )
      asst = wire[0]
      expect(asst.keys).to match_array(%i[role content tool_calls])
      expect(asst[:tool_calls][0].dig(:function, :arguments)).to eq('{"command":"id"}')
      tool = wire[1]
      expect(tool[:content]).to eq('{"success":true,"result":"uid=0"}')
    end
  end

  describe '.ollama_wire_messages' do
    it 'parses JSON-string function.arguments into a Hash and coerces nil content' do
      wire = described_class.ollama_wire_messages(
        messages: [
          {
            role: 'assistant',
            content: nil,
            _text_tool_coerced: true,
            thinking: 'secret',
            tool_calls: [
              {
                id: 'c1',
                type: 'function',
                function: { name: 'shell', arguments: '{"command":"id"}' }
              }
            ]
          },
          {
            role: 'tool',
            tool_call_id: 'c1',
            name: 'shell',
            content: { success: true, result: 'uid=0' }
          }
        ]
      )
      asst = wire[0]
      expect(asst.keys).to match_array(%i[role content tool_calls])
      expect(asst[:content]).to eq('')
      expect(asst[:tool_calls][0].dig(:function, :arguments)).to eq(command: 'id')
      tool = wire[1]
      expect(tool[:content]).to eq('{"success":true,"result":"uid=0"}')
    end

    it 'passes through Hash function.arguments unchanged' do
      wire = described_class.ollama_wire_messages(
        messages: [
          {
            role: 'assistant',
            content: '',
            tool_calls: [
              {
                id: 'c2',
                type: 'function',
                function: { name: 'shell', arguments: { command: 'uname' } }
              }
            ]
          }
        ]
      )
      expect(wire[0].dig(:tool_calls, 0, :function, :arguments)).to eq(command: 'uname')
    end
  end
end
