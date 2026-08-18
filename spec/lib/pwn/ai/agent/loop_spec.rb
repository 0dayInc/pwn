# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe PWN::AI::Agent::Loop do # rubocop:disable Metrics/BlockLength
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

    it 'does not keep injecting English focus after the plan is covered' do
      src = File.read(described_class.method(:inject_task_focus!).source_location.first)
      focus = src[/private_class_method def self\.inject_task_focus!.*?private_class_method def self\.\w+/m]
      focus ||= src
      expect(focus).to match(/plan_open\?/)
    end

    it 'does not tell an open English plan to stop after 3 tools just because budget is hot' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/budget_exhaustion_hot\?/)
      expect(src).to match(/plan_open\?/)
      # local ≤3-tool abort is only for a closed/short plan, not mid-goal.
      expect(src).to match(/english_open|plan_open\?/)
    end

    it 'parks stale extra budget scars even while the host is hot' do
      tmp = Dir.mktmpdir
      stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(tmp, 'mistakes.json'))
      PWN::AI::Agent::Mistakes.reset if PWN::AI::Agent::Mistakes.respond_to?(:reset)
      a = PWN::AI::Agent::Mistakes.record(
        tool: 'agent_loop',
        error: '[pwn-ai] iteration budget exhausted A',
        shape: 'budget_exhausted'
      )
      b = PWN::AI::Agent::Mistakes.record(
        tool: 'agent_loop',
        error: '[pwn-ai] iteration budget exhausted B',
        shape: 'budget_exhausted'
      )
      described_class.send(:maybe_park_budget_scars!)
      parked_n = [a, b].count do |m|
        PWN::AI::Agent::Mistakes.find(signature: m[:signature])[:parked]
      end
      expect(parked_n).to be >= 1
    ensure
      FileUtils.remove_entry(tmp) if tmp && Dir.exist?(tmp)
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
        { role: 'tool', content: '{"success":true,"result":{"stdout":"patched loop.rb\n0 offenses detected"}}' }
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

      # plan_idx on last item is not enough if mutate/verify English tasks lack evidence
      r_idx_only = loop_mod.send(
        :evidence_enough_to_finalize?,
        messages: msgs, turn_fails: {}, i: 5, max_iters: 40,
        request: 'fix p17', plan_steps: 3, ts_state: last_plan
      )
      expect(r_idx_only).to be false

      # call site must pass ts_state
      src = File.read(loop_mod.method(:run).source_location.first)
      expect(src).to match(/evidence_enough_to_finalize\?\([\s\S]*?ts_state: ts_state/)
      expect(src).to match(/original request|request is the completion/i)
    end

    it 'P17 does not inject finalize while implement/verify English tasks remain open' do
      loop_mod = described_class
      ls_find = [
        { role: 'user', content: 'map then implement then verify' },
        { role: 'tool', name: 'shell', content: '{"success":true,"result":{"stdout":"ls: loop.rb","exit":0}}' },
        { role: 'tool', name: 'shell', content: '{"success":true,"result":{"stdout":"find: task_summarizer.rb","exit":0}}' },
        { role: 'tool', name: 'shell', content: '{"success":true,"result":{"stdout":"resolved file listing","exit":0}}' }
      ]
      mid = {
        plan: [
          'Map how tasks complete',
          'Implement the completion fix',
          'Verify full task completion end-to-end'
        ],
        plan_idx: 0
      }

      r_active = loop_mod.send(
        :evidence_enough_to_finalize?,
        messages: ls_find, turn_fails: {}, i: 4, max_iters: 40,
        request: 'map then implement then verify', plan_steps: 3, ts_state: mid
      )
      expect(r_active).to be false

      jumped = mid.merge(plan_idx: 2)
      r_jumped = loop_mod.send(
        :evidence_enough_to_finalize?,
        messages: ls_find, turn_fails: {}, i: 4, max_iters: 40,
        request: 'map then implement then verify', plan_steps: 3, ts_state: jumped
      )
      expect(r_jumped).to be false
      expect(
        PWN::AI::Agent::TaskSummarizer.plan_open?(state: jumped, messages: ls_find)
      ).to eq true
      left = PWN::AI::Agent::TaskSummarizer.unfinished_tasks(state: jumped, messages: ls_find)
      expect(left.map { |t| t[:item] }.join(' ')).to match(/Implement|Verify/i)

      src = File.read(loop_mod.method(:run).source_location.first)
      expect(src).to match(/Write the complete final answer now/)
      expect(src).to match(/evidence_enough_to_finalize\?/)
      expect(src).to match(/Do NOT call more tools/)
    end

    it 'P17 can early-final when English tasks are covered even if plan_idx is still 0' do
      loop_mod = described_class
      done = {
        plan: [
          'Determine the local hostname',
          'Present the result and report completion'
        ],
        plan_idx: 0
      }
      msgs = [
        { role: 'user', content: 'what is my hostname?' },
        { role: 'tool', name: 'shell', content: '{"success":true,"result":{"stdout":"kali-box","exit":0}}' },
        { role: 'tool', name: 'shell', content: '{"success":true,"result":{"stdout":"kali-box","exit":0}}' }
      ]
      expect(
        PWN::AI::Agent::TaskSummarizer.plan_open?(state: done, messages: msgs)
      ).to eq false
      r = loop_mod.send(
        :evidence_enough_to_finalize?,
        messages: msgs, turn_fails: {}, i: 4, max_iters: 40,
        request: 'what is my hostname?', plan_steps: 2, ts_state: done
      )
      expect(r).to be true
    end

    it 'P17 can early-final a finished request even while advisory English tasks remain' do
      loop_mod = described_class
      leftover_plan = {
        plan: [
          'Determine the local hostname',
          'run rspec to verify'
        ],
        plan_idx: 0
      }
      msgs = [
        { role: 'user', content: 'what is my hostname?' },
        { role: 'tool', name: 'shell', content: '{"success":true,"result":{"stdout":"kali-box","exit":0}}' },
        { role: 'tool', name: 'shell', content: '{"success":true,"result":{"stdout":"kali-box","exit":0}}' }
      ]
      expect(
        PWN::AI::Agent::TaskSummarizer.plan_open?(state: leftover_plan, messages: msgs)
      ).to eq true
      r = loop_mod.send(
        :evidence_enough_to_finalize?,
        messages: msgs, turn_fails: {}, i: 4, max_iters: 40,
        request: 'what is my hostname?', plan_steps: 2, ts_state: leftover_plan
      )
      expect(r).to be true
    end

    it 'open_plan_blocks_final? does not govern completion — the original request does' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/original request is the completion signal/i)
      expect(src).not_to match(/if open_plan_blocks_final\?/)
    end

    it 'request_unsatisfied? uses request-shaped evidence, not just mutation regex' do
      ls_only = [
        { role: 'user', content: 'write complete into /tmp/x.txt and verify it' },
        {
          role: 'assistant',
          tool_calls: [
            { function: { name: 'shell', arguments: '{"command":"ls /tmp"}' } }
          ]
        },
        { role: 'tool', name: 'shell', content: '{"success":true,"result":{"stdout":"x","exit":0}}' }
      ]
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: 'Write complete into /tmp/x.txt and verify it reads complete',
          messages: ls_only,
          last_iter: false
        )
      ).to eq true
      # Path-shaped write without the old printf/sed regex still satisfies the request.
      written = ls_only + [
        {
          role: 'assistant',
          tool_calls: [
            { function: { name: 'shell', arguments: '{"command":"python3 -c \\"open(\'/tmp/x.txt\',\'w\').write(\'complete\')\\""}' } }
          ]
        },
        {
          role: 'tool',
          name: 'shell',
          content: '{"success":true,"result":{"stdout":"","stderr":"","exit":0}}'
        }
      ]
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: 'Write complete into /tmp/x.txt and verify it reads complete',
          messages: written,
          last_iter: false
        )
      ).to eq false
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: 'what is my hostname?',
          messages: [
            { role: 'tool', name: 'shell', content: '{"success":true,"result":{"stdout":"kali","exit":0}}' }
          ],
          last_iter: false
        )
      ).to eq false
    end

    it 'does not bounce world-knowledge asks that need no host work' do
      expect(described_class.needs_host_work?(request: 'what color is a cherry')).to eq false
      expect(described_class.world_knowledge?(request: 'what color is a cherry')).to eq true
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: 'what color is a cherry',
          messages: [{ role: 'assistant', content: 'Red.', tool_calls: [] }],
          last_iter: false
        )
      ).to eq false
      expect(described_class.needs_host_work?(request: 'Write hello into /tmp/x.txt')).to eq true
    end

    it 'last-iter strips tools only on the true last slot; leftover English tasks do not force required' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/text_only_iters = 1/)
      expect(src).not_to match(/english_open && hot/)
      expect(src).to match(/has_tool_result \|\| !need_tools \? 'auto' : 'required'/)
      expect(src).not_to match(/still_acting/)
    end

    it 'Loop.run default tool pool is CORE_TOOLS, not the full registry' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/fetch\(:core_only,\s*true\)/)
      expect(src).to match(/core_only:/)
      expect(src).to match(/CORE_TOOLS/)
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
      # After the first tool result, auto. English leftovers do not keep required.
      expect(src).to match(/has_tool_result \|\| !need_tools \? 'auto' : 'required'/)
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

  describe 'intent routing (ollama/openwebui how-to + recon guard)' do
    it 'classifies pure how-to vs live recon vs act' do
      expect(described_class.request_intent(request: 'how to do a ping sweep of a subnet using hping3?')).to eq(:howto)
      expect(described_class.request_intent(request: 'using hping3 what live hosts can you find in this subnet?')).to eq(:recon_act)
      expect(described_class.request_intent(request: 'refactor Loop.run and run rubocop')).to eq(:act)
    end

    it 'does not classify request types — Loop has no request_kind' do
      expect(described_class).not_to respond_to :request_kind
    end

    it 'run does not short-circuit statement/question — they take the full tool loop' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).not_to match(/kind\.to_sym == :statement/)
      expect(src).not_to match(/kind\.to_sym == :question/)
      expect(src).not_to match(/Request type/)
      expect(src).to match(/Every request gets a task compass/)
    end

    it 'classifies pure prior-turn recall and vague memory cues as :recall' do
      expect(described_class.request_intent(request: 'what did I just say?')).to eq(:recall)
      expect(described_class.request_intent(request: 'What did I just say')).to eq(:recall)
      expect(described_class.request_intent(request: 'what was my last request?')).to eq(:recall)
      expect(described_class.request_intent(request: 'remind me what I said')).to eq(:recall)
      expect(described_class.request_intent(request: 'how did you respond to what I just said?')).to eq(:recall)
      expect(described_class.request_intent(request: 'what did you just say?')).to eq(:recall)
      expect(described_class.request_intent(request: 'what was your last answer?')).to eq(:recall)
      # Doing-verb keeps full agent work
      expect(
        described_class.request_intent(
          request: 'remember what I said about nmap and implement the scanner fix'
        )
      ).to eq(:act)
    end

    it 'classifies pure greetings and light weather smalltalk as :greeting' do
      expect(described_class.request_intent(request: 'hi')).to eq(:greeting)
      expect(described_class.request_intent(request: 'Hello!')).to eq(:greeting)
      expect(described_class.request_intent(request: "Howdy, it's cloudy.")).to eq(:greeting)
      expect(described_class.request_intent(request: 'good morning')).to eq(:greeting)
      expect(described_class.request_intent(request: "hey how's it going")).to eq(:greeting)
      # Security work with a leading hi stays full agent work
      expect(described_class.request_intent(request: 'hi, please refactor Loop.run')).to eq(:act)
      expect(described_class.request_intent(request: 'how to do a ping sweep with hping3?')).to eq(:howto)
    end

    it 'recon_authorized? requires scope language or env flag' do
      expect(described_class.recon_authorized?(request: 'find live hosts on this subnet')).to eq(false)
      expect(described_class.recon_authorized?(request: 'authorized engagement: find live hosts on this lab subnet')).to eq(true)
      allow(PWN::Env).to receive(:dig).and_call_original
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :recon_authorized).and_return(true)
      expect(described_class.recon_authorized?(request: 'find live hosts')).to eq(true)
    end

    it 'run short-circuits how-to without plan_first or tools' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/request_intent/)
      expect(src).not_to match(/request_kind/)
      expect(src).to match(/answer_howto/)
      expect(src).to match(/intent == :howto/)
      expect(src).to match(/skip_plan/)
    end

    it 'answer_howto does not register shell tool use in source path' do
      src = File.read(described_class.method(:run).source_location.first)
      # how-to return happens before task_summary_plan!
      expect(src).to match(/if intent == :howto.*?return answer_howto/m)
    end

    it 'run short-circuits pure recall via answer_recall before plan_first' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/RECALL_RX/)
      expect(src).to match(/answer_recall/)
      expect(src).to match(/intent == :recall.*?return answer_recall/m)
      expect(src).to match(/skip_plan/)
      expect(src).not_to match(/request_kind/)
    end

    it 'run short-circuits greetings via answer_greeting before plan_first' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/GREETING_RX/)
      expect(src).to match(/answer_greeting/)
      expect(src).to match(/intent == :greeting.*?return answer_greeting/m)
      expect(src).to match(/skip_plan/)
      expect(src).not_to match(/request_kind/)
    end

    it 'answer_greeting returns fixed ack without weather echo or tools' do
      sess_tmp = Dir.mktmpdir('pwn-sess-greet')
      stub_const('PWN::Sessions::SESSIONS_DIR', sess_tmp)
      sid = 'greet_spec_sess'
      PWN::Sessions.create(id: sid, title: 'greet-spec')
      allow(described_class).to receive(:should_auto_introspect?).and_return(false)
      allow(described_class).to receive(:plan_first).and_raise('plan_first must not run on greeting')
      out = described_class.send(
        :answer_greeting,
        request: "Howdy, it's cloudy.",
        session_id: sid
      )
      expect(out).to match(/acknowledged|ready/i)
      expect(out).not_to match(/cloudy out there|noted, cloudy|Howdy —/i)
      expect(out).not_to match(/plan_first|shell\(/i)
      run_out = described_class.run(
        request: "Howdy, it's cloudy.",
        session_id: sid,
        system_role_content: 'test system'
      )
      expect(run_out).to eq(out)
      expect(run_out).not_to match(/cloudy out there/i)
    ensure
      FileUtils.rm_rf(sess_tmp) if sess_tmp
    end

    it 'answer_recall returns prior user text from the session without tools' do
      sess_tmp = Dir.mktmpdir('pwn-sess-recall')
      stub_const('PWN::Sessions::SESSIONS_DIR', sess_tmp)
      sid = 'recall_spec_sess'
      PWN::Sessions.create(id: sid, title: 'recall-user-spec')
      PWN::Sessions.append(session_id: sid, role: 'user', content: 'THIS WAS MY LAST REQUEST. THIS IS A TEST OF MEMORY RECALL.')
      PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'ack prior asst')
      # Avoid side-effect introspect noise
      allow(described_class).to receive(:should_auto_introspect?).and_return(false)
      out = described_class.send(
        :answer_recall,
        request: 'what did I just say?',
        session_id: sid,
        system_role_content: 'test'
      )
      expect(out).to include('THIS WAS MY LAST REQUEST. THIS IS A TEST OF MEMORY RECALL.')
      expect(out).to match(/you just said/i)
    ensure
      FileUtils.rm_rf(sess_tmp) if sess_tmp
    end

    it 'answer_recall returns prior assistant text for how-did-you-respond without tools' do
      sess_tmp = Dir.mktmpdir('pwn-sess-recall-asst')
      stub_const('PWN::Sessions::SESSIONS_DIR', sess_tmp)
      sid = 'recall_spec_asst'
      PWN::Sessions.create(id: sid, title: 'recall-asst-spec')
      PWN::Sessions.append(session_id: sid, role: 'user', content: 'this is a test.')
      PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'Acknowledged — test message received.')
      allow(described_class).to receive(:should_auto_introspect?).and_return(false)
      out = described_class.send(
        :answer_recall,
        request: 'how did you respond to what I just said?',
        session_id: sid,
        system_role_content: 'test'
      )
      expect(out).to include('Acknowledged — test message received.')
      expect(out).to match(/prior assistant response|I responded:/i)
      # Must not re-enter multi-tool scaffolding markers
      expect(out).not_to match(/plan_first|shell\(/i)
    ensure
      FileUtils.rm_rf(sess_tmp) if sess_tmp
    end

    it 'answer_recall resolves how-did-you-respond-when-I-said across nested meta pairs' do
      sess_tmp = Dir.mktmpdir('pwn-sess-recall-nested')
      stub_const('PWN::Sessions::SESSIONS_DIR', sess_tmp)
      sid = 'recall_spec_nested'
      PWN::Sessions.create(id: sid, title: 'recall-nested')
      PWN::Sessions.append(session_id: sid, role: 'user', content: 'howdy ho from down below!')
      PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'Howdy ho right back! System is up on Kali.')
      PWN::Sessions.append(session_id: sid, role: 'user', content: 'what did I just say?')
      PWN::Sessions.append(session_id: sid, role: 'assistant', content: "You just said:\n\nhowdy ho from down below!")
      PWN::Sessions.append(session_id: sid, role: 'user', content: 'and what did you say when I said that?')
      PWN::Sessions.append(
        session_id: sid,
        role: 'assistant',
        content: "Immediately prior user message:\nwhat did I just say?\n\nImmediately prior assistant response:\nYou just said:\n\nhowdy ho from down below!"
      )
      allow(described_class).to receive(:should_auto_introspect?).and_return(false)

      out = described_class.send(
        :answer_recall,
        request: 'how did you respond when I said, `howdy ho from down below!`?',
        session_id: sid,
        system_role_content: 'test'
      )
      expect(out).to include('Howdy ho right back! System is up on Kali.')
      expect(out).to include('howdy ho from down below!')
      expect(out).not_to include('what did I just say?')
      expect(out).not_to match(/plan_first|shell\(/i)

      out2 = described_class.send(
        :answer_recall,
        request: 'and what did you say when I said that?',
        session_id: sid,
        system_role_content: 'test'
      )
      expect(out2).to include('Howdy ho right back! System is up on Kali.')
      expect(out2).not_to match(/Immediately prior user message:\nwhat did I just say/i)
    ensure
      FileUtils.rm_rf(sess_tmp) if sess_tmp
    end

    it 'Loop.run short-circuits pure recall without plan_first or TaskSummarizer tools' do
      sess_tmp = Dir.mktmpdir('pwn-sess-recall-run')
      stub_const('PWN::Sessions::SESSIONS_DIR', sess_tmp)
      sid = 'recall_run_spec'
      PWN::Sessions.create(id: sid, title: 'recall-run')
      PWN::Sessions.append(session_id: sid, role: 'user', content: 'SHIP MARKER ALPHA')
      PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'SHIP MARKER BETA ASST')
      allow(described_class).to receive(:should_auto_introspect?).and_return(false)
      allow(described_class).to receive(:plan_first).and_raise('plan_first must not run on pure recall')
      allow(PWN::AI::Agent::TaskSummarizer).to receive(:emit_plan!).and_raise('emit_plan must not run on pure recall') if defined?(PWN::AI::Agent::TaskSummarizer)
      out = described_class.run(
        request: 'what did I just say?',
        session_id: sid,
        system_role_content: 'test system'
      )
      expect(out).to include('SHIP MARKER ALPHA')
      out2 = described_class.run(
        request: 'how did you respond to what I just said?',
        session_id: sid,
        system_role_content: 'test system'
      )
      # After first recall, prior assistant becomes the first recall answer;
      # ensure second path still short-circuits (no plan_first raise).
      expect(out2).to be_a(String)
      expect(out2).not_to be_empty
    ensure
      FileUtils.rm_rf(sess_tmp) if sess_tmp
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

  it 'Loop.run finishes the original request; English tasks are advisory only' do
    src = File.read(described_class.method(:run).source_location.first)
    expect(src).to match(/original request is the completion signal/i)
    expect(src).not_to match(/do NOT finalize/i)
    expect(src).not_to match(/if open_plan_blocks_final\?/)
  end

  it 'Loop.run marks the Hermes user-path so TurnFinalizer can defer' do
    src = File.read(described_class.method(:run).source_location.first)
    expect(src).to match(/TurnFinalizer\.enter_user_path!/)
    expect(src).to match(/TurnFinalizer\.leave_user_path!/)
  end

  it 'should_auto_introspect skips cheap greeting/howto/recall answers' do
    src = File.read(described_class.method(:run).source_location.first)
    expect(src).to include('return false if %i[greeting howto recall].include?(intent)')
    expect(src).not_to include('return false if kind == :statement')
    expect(src).not_to include('return false if kind == :question && fails.zero?')
  end
end # rubocop:enable Metrics/BlockLength
