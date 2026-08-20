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

  describe 'RL-adjacent loop contracts' do # rubocop:disable Metrics/BlockLength
    it 'spins on engine HTTP wait and still dispatches on_tool (debug must not hide the TUI)' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/spinner:\s*true/)
      expect(src).to match(/on_tool&?\.call/)
      expect(src).not_to match(/on_tool\s*=\s*nil/)
    end

    it 'does not treat a round cap as a finished answer' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).not_to match(/iteration budget exhausted/)
      expect(src).not_to match(/final budget_exhausted/)
      expect(src).not_to match(/shape: :budget_exhausted/)
      expect(src).not_to match(/max_iters\.times/)
      expect(src).to match(/may_finalize\?/)
      expect(src).to match(/loop do/)
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
        {
          role: 'assistant',
          tool_calls: [{ function: { name: 'shell', arguments: '{"command":"sed -i s/x/y/ loop.rb"}' } }]
        },
        {
          role: 'tool',
          name: 'shell',
          content: '{"success":true,"effect":"write","result":{"stdout":"patched loop.rb","exit":0}}'
        },
        {
          role: 'assistant',
          tool_calls: [{ function: { name: 'shell', arguments: '{"command":"ruby -c loop.rb"}' } }]
        },
        {
          role: 'tool',
          name: 'shell',
          content: '{"success":true,"effect":"read","result":{"stdout":"Syntax OK","exit":0}}'
        }
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
      expect(src).not_to match(/Do NOT call more tools/)
      expect(src).to match(/may_finalize\?/)
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
        { role: 'tool', name: 'shell', content: '{"success":true,"effect":"read","result":{"stdout":"kali-box","exit":0}}' },
        { role: 'tool', name: 'shell', content: '{"success":true,"effect":"read","result":{"stdout":"kali-box","exit":0}}' }
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
        { role: 'tool', name: 'shell', content: '{"success":true,"effect":"read","result":{"stdout":"kali-box","exit":0}}' },
        { role: 'tool', name: 'shell', content: '{"success":true,"effect":"read","result":{"stdout":"kali-box","exit":0}}' }
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
      ).to eq true
      verified = written + [
        {
          role: 'assistant',
          tool_calls: [
            { function: { name: 'shell', arguments: '{"command":"cat /tmp/x.txt"}' } }
          ]
        },
        {
          role: 'tool',
          name: 'shell',
          content: '{"success":true,"effect":"read","result":{"stdout":"complete","exit":0}}'
        }
      ]
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: 'Write complete into /tmp/x.txt and verify it reads complete',
          messages: verified,
          last_iter: false
        )
      ).to eq false
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: 'what is my hostname?',
          messages: [
            { role: 'tool', name: 'shell', content: '{"success":true,"effect":"read","result":{"stdout":"kali","exit":0}}' }
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

    it 'skips the implement compass on a browse/navigate request' do
      req = 'Navigate to https://0dayinc.com using TransparentBrowser.open and list blog URLs'
      expect(described_class.send(:request_need, request: req)).to eq :browse
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/skip_compass = .*browse/)
    end

    it 'does not bounce a text-only turn for missing tool evidence' do
      req = 'Navigate to https://0dayinc.com using TransparentBrowser.open and list blog URLs'
      expect(described_class.needs_host_work?(request: req)).to eq true
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: req,
          messages: [{ role: 'assistant', content: 'SOUND — step 1 is the likely fail.', tool_calls: [] }]
        )
      ).to eq true
      Thread.current[:pwn_loop_no_tools] = true
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: req,
          messages: [{ role: 'assistant', content: 'SOUND — step 1 is the likely fail.', tool_calls: [] }]
        )
      ).to eq false
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/pwn_loop_no_tools/)
      expect(src).to match(/skip_compass = .*no_tools/)
    ensure
      Thread.current[:pwn_loop_no_tools] = nil
    end

    it 'does not start post-answer review from a nested or tool-less Loop.run' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/!nested && !no_tools && should_auto_introspect\?/)
      expect(
        described_class.send(
          :should_auto_introspect?,
          local: false,
          turn_fails: {},
          iter: 1
        )
      ).to eq true
      Thread.current[:pwn_loop_no_tools] = true
      expect(
        described_class.send(
          :should_auto_introspect?,
          local: false,
          turn_fails: {},
          iter: 1
        )
      ).to eq false
    ensure
      Thread.current[:pwn_loop_no_tools] = nil
    end

    it 'writes full tool request/result to the debug log and timestamps Interrupt' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/debug_tool_io!/)
      expect(src).to match(/tool #\{name\} start/)
      expect(src).to match(/rescue Interrupt/)
      expect(src).to match(/note_interrupt!/)
      expect(src).to match(/note_exception!/)
      expect(src).to match(/rescue StandardError/)
      expect(src).to include("debug_progress(msg: 'engine returned no message')")
      expect(src).not_to match(/dispatch #\{name\} ok_len=/)
    end

    it 'records a reconstruct-first timeout mistake instead of treating success:true as ok' do
      tmp = Dir.mktmpdir
      stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(tmp, 'mistakes.json'))
      raw = JSON.generate(
        success: true,
        result: { stdout: '', error: 'timeout after 20s', hint: 'x', scenario: 'construction' }
      )
      tele = described_class.send(
        :record_metrics,
        name: 'pwn_eval',
        started: Time.now,
        raw: raw,
        args: '{"code":"sleep 3"}'
      )
      expect(tele[:ok]).to eq false
      expect(tele[:mistake]).to be_a(Hash)
      expect(tele[:mistake][:error].to_s).to match(/reconstruct/)
      expect(tele[:mistake][:shape].to_s).to eq('timeout')
    end

    it 'treats a skills-catalog ask as recall, not trivia or host-work' do
      req = 'what skills are available?'
      expect(described_class.catalog_lookup?(request: req)).to eq true
      expect(described_class.world_knowledge?(request: req)).to eq false
      expect(described_class.needs_host_work?(request: req)).to eq false
      expect(described_class.send(:request_need, request: req)).to eq :read
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: req,
          messages: [{ role: 'assistant', content: '103 skills…', tool_calls: [] }]
        )
      ).to eq true
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: req,
          messages: [
            {
              role: 'assistant',
              content: '',
              tool_calls: [
                { function: { name: 'skills_recall', arguments: '{}' } }
              ]
            }
          ]
        )
      ).to eq false
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/skip_plan.*catalog/)
      expect(src).to match(/force_plan && cal_state\[:cal\] && !skip_plan/)
    end

    it 'does not treat rspec/rubocop green as a finished write/docs ask' do
      req = 'Update all markdown files to reflect operational changes and rebuild diagrams'
      verified = [
        { role: 'user', content: req },
        { role: 'tool', name: 'shell', content: '4 files inspected, no offenses detected' },
        { role: 'tool', name: 'shell', content: "Finished in 0.60 seconds\n12 examples, 0 failures\n" }
      ]
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: req,
          messages: verified,
          last_iter: false
        )
      ).to eq true
      expect(
        described_class.send(
          :evidence_enough_to_finalize?,
          request: req,
          messages: verified,
          turn_fails: {},
          i: 5,
          max_iters: 75,
          plan_steps: 5
        )
      ).to eq false
      leftover = <<~TXT
        File writes were not applied in this turn because the run was forced
        to a final answer before those writes. Resume from the table above.
      TXT
      expect(described_class.send(:incomplete_final?, text: leftover, last_iter: false)).to eq true
    end

    it 'does not treat a README HTML listing as a finished docs regen' do
      req = 'regenerate documentation and update README.md'
      listing = <<~HTML
        <p align="center">
          <img src="documentation/pwn.gif">
        </p>
      HTML
      rant = 'Documentation pass is inventoried. File writes and diagram rebuilds were not applied in this turn. I will do that next time.'
      msgs = [
        { role: 'tool', name: 'shell', content: listing },
        { role: 'assistant', content: rant }
      ]
      expect(described_class.needs_host_work?(request: req)).to eq true
      expect(described_class.needs_host_work?(request: 'regenerate documentation')).to eq true
      expect(
        described_class.send(:request_unsatisfied?, request: req, messages: msgs)
      ).to eq true
      expect(described_class.send(:incomplete_final?, text: rant, last_iter: false)).to eq true
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/Dispatch\.effect|tool_effects/)
      expect(src).not_to match(/blob\.match\?\(MUTATION_EVIDENCE_RX\)/)
    end

    it 'keeps tools for any unfinished host-work request — no last-iter strip' do
      req = 'Update all markdown files and rebuild diagrams'
      verified = [
        { role: 'tool', name: 'shell', content: "12 examples, 0 failures\n" }
      ]
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: req,
          messages: verified,
          last_iter: true
        )
      ).to eq true
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).not_to match(/last_iter = want_last && !still_open/)
      expect(src).to match(/call_engine\(messages: messages, tools: tools/)
    end

    it 'never accepts a text final while the original host-work request is unsatisfied' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).not_to match(/turn_fails\['unsatisfied'\]\.to_i < 4/)
      expect(src).to match(/Keep calling CORE_TOOLS/)
      req = 'Update all markdown files and rebuild diagrams'
      wrap = [{ role: 'assistant', content: 'Remaining block. Forced to a final.' }]
      expect(
        described_class.send(:request_unsatisfied?, request: req, messages: wrap, last_iter: false)
      ).to eq true
      expect(
        described_class.send(
          :evidence_enough_to_finalize?,
          request: req,
          messages: wrap + [
            { role: 'tool', name: 'shell', content: "12 examples, 0 failures\n" },
            { role: 'tool', name: 'shell', content: "12 examples, 0 failures\n" },
            { role: 'tool', name: 'shell', content: "12 examples, 0 failures\n" }
          ],
          turn_fails: {},
          i: 5,
          max_iters: 75,
          plan_steps: 5
        )
      ).to eq false
    end

    it 'does not shrink max_iters because prior budget scars are hot' do
      src = File.read(described_class.method(:max_iters).source_location.first)
      expect(src).not_to match(/hot_cap = local_engine\? \? 24 : 75/)
      expect(src).not_to match(/n = \[n, hot_cap\]\.min/)
    end

    it 'does not treat memory_remember as a finished docs write' do
      req = 'Update all markdown files and rebuild diagrams'
      msgs = [
        { role: 'tool', name: 'memory_remember', content: '{"success":true,"effect":"store","result":{"saved":true}}' },
        { role: 'tool', name: 'learning_note_outcome', content: '{"success":true,"effect":"store"}' }
      ]
      expect(
        described_class.send(:request_unsatisfied?, request: req, messages: msgs)
      ).to eq true
    end

    it 'never aborts an open host-work request with the budget thrash canned string' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).not_to match(/fail_n\s*=\s*turn_fails\.values\.sum/)
      expect(src).to match(/BOUNCE_FAIL_KEYS|dispatch_fail_n/)
      expect(src).not_to match(/return msg\n.*budget thrash/m)
    end

    it 'never accepts a text final while a long host-work request is still open' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).not_to match(/incomplete_final\?.*< 4/)
      expect(src).not_to match(/Do NOT call more tools/)
      expect(src).to match(/may_finalize\?/)
      req = 'test the in-scope authorized bug bounty program end to end'
      listing = [
        { role: 'tool', name: 'shell', content: '{"success":true,"effect":"read","result":{"stdout":"ls"}}' }
      ]
      expect(described_class.send(:request_need, request: req)).to eq :any
      expect(described_class.send(:request_unsatisfied?, request: req, messages: listing)).to eq true
      expect(
        described_class.send(
          :may_finalize?,
          request: req,
          messages: listing,
          text: 'I will do the rest next time.',
          last_iter: true
        )
      ).to eq false
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/OpenGoal/)
      expect(src).to match(/write_verified\?/)
    end

    it 'does not treat https URLs as file paths; browser collect asks complete on URL evidence' do
      req = <<~REQ.gsub(/\s+/, ' ').strip
        Navigate to https://0dayinc.com using TransparentBrowser.open(browser_type: :chrome, devtools: true)
        find all the blog posts ever made, and return a list of URLs.
        Once complete close the browser via TransparentBrowser.close
      REQ
      expect(req.scan(described_class::HOST_PATH_RX)).to eq([])
      expect(described_class.needs_host_work?(request: req)).to eq true
      expect(described_class.world_knowledge?(request: req)).to eq false
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: req,
          messages: [{ role: 'assistant', content: 'opening chrome', tool_calls: [] }],
          last_iter: false
        )
      ).to eq true
      collected = [
        {
          role: 'assistant',
          tool_calls: [{ function: { name: 'pwn_eval', arguments: '{"code":"browser.goto"}' } }]
        },
        {
          role: 'tool',
          name: 'pwn_eval',
          content: '{"success":true,"result":["https://0dayinc.com/blog/one","https://0dayinc.com/blog/two"]}'
        }
      ]
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: req,
          messages: collected,
          last_iter: false
        )
      ).to eq false
    end

    it 'does not strip tools on a last slot; leftover English tasks do not force required' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).not_to match(/text_only_iters = 1/)
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
      expect(described_class.send(:incomplete_final?, text: sample, last_iter: true)).to eq(true)
      expect(
        described_class.send(
          :incomplete_final?,
          text: 'Live hosts: 10.3.3.1 via sudo hping3 -1 -c 1 on 10.3.3.0/27.',
          last_iter: false
        )
      ).to eq(false)
    end

    it 'flags heading-only remaining-block stubs as incomplete, even on last_iter' do
      [
        '# Remaining block',
        "# Remaining block\n",
        "```\n# Remaining block\n```",
        'Remaining block'
      ].each do |sample|
        expect(described_class.send(:incomplete_final?, text: sample, last_iter: false)).to eq(true), sample.inspect
        expect(described_class.send(:incomplete_final?, text: sample, last_iter: true)).to eq(true), sample.inspect
      end
      expect(
        described_class.send(
          :incomplete_final?,
          text: 'A ripe cherry is typically red.',
          last_iter: false
        )
      ).to eq(false)
    end
  end

  describe 'intent routing (how-to + greeting + recall)' do
    it 'classifies pure how-to vs live recon vs act' do
      expect(described_class.request_intent(request: 'how to do a ping sweep of a subnet using hping3?')).to eq(:howto)
      expect(described_class.request_intent(request: 'using hping3 what live hosts can you find in this subnet?')).to eq(:recon_act)
      expect(described_class.request_intent(request: 'refactor Loop.run and run rubocop')).to eq(:act)
    end

    it 'does not classify request types — Loop has no request_kind' do
      expect(described_class).not_to respond_to :request_kind
    end

    it 'does not invent a request type for world-knowledge; the full loop still accepts a text final' do
      expect(described_class.world_knowledge?(request: 'what color is a passion fruit?')).to eq true
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).not_to match(/request_kind/)
      expect(src).not_to match(/world_knowledge\?.*?return answer_question/m)
      expect(src).to match(/world_knowledge\?/)
    end

    it 'full tool loop accepts a text final for world-knowledge with no host-work tools' do
      expect(described_class.world_knowledge?(request: 'what color is a passion fruit?')).to eq true
      expect(described_class.send(:request_need, request: 'what color is a passion fruit?')).to eq :none
      expect(
        described_class.send(
          :request_unsatisfied?,
          request: 'what color is a passion fruit?',
          messages: [{ role: 'assistant', content: 'Purple when ripe.', tool_calls: [] }]
        )
      ).to eq false
      sess_tmp = Dir.mktmpdir('pwn-sess-fruit')
      stub_const('PWN::Sessions::SESSIONS_DIR', sess_tmp)
      sid = 'fruit_spec'
      PWN::Sessions.create(id: sid, title: 'fruit')
      allow(described_class).to receive(:should_auto_introspect?).and_return(false)
      allow(described_class).to receive(:plan_first).and_raise('plan_first must not run on world-knowledge')
      allow(PWN::AI::Agent::TaskSummarizer).to receive(:enabled?).and_return(false) if defined?(PWN::AI::Agent::TaskSummarizer)
      allow(described_class).to receive(:call_engine).and_return(
        { role: 'assistant', content: 'Purple when ripe.', tool_calls: [] }
      )
      out = described_class.run(
        request: 'what color is a passion fruit?',
        session_id: sid,
        system_role_content: 'test system'
      )
      expect(out).to include('Purple when ripe.')
    ensure
      FileUtils.rm_rf(sess_tmp) if sess_tmp
    end

    it 'sends this session conversation as LLM messages without a recall-cue regex' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/to_llm_messages|session_chat_history/)
      expect(src).not_to match(/VAGUE_MEMORY_RX.*?to_llm_messages/m)
      sess_tmp = Dir.mktmpdir('pwn-sess-hist')
      stub_const('PWN::Sessions::SESSIONS_DIR', sess_tmp)
      sid = 'hist_run_spec'
      PWN::Sessions.create(id: sid, title: 'hist-run')
      PWN::Sessions.append(session_id: sid, role: 'user', content: 'where is OpenGoal implemented?')
      PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'lib/pwn/ai/agent/open_goal.rb')
      seen = []
      allow(described_class).to receive(:should_auto_introspect?).and_return(false)
      allow(described_class).to receive(:plan_first).and_return(nil)
      allow(PWN::AI::Agent::TaskSummarizer).to receive(:enabled?).and_return(false) if defined?(PWN::AI::Agent::TaskSummarizer)
      allow(described_class).to receive(:call_engine) do |opts|
        seen = Array(opts[:messages])
        { role: 'assistant', content: 'in loop.rb Loop.run', tool_calls: [] }
      end
      out = described_class.run(
        request: 'where is this logic implemented in /opt/pwn when using pwn-ai',
        session_id: sid,
        system_role_content: 'test system'
      )
      expect(out).to include('in loop.rb Loop.run')
      expect(seen.map { |m| m[:content].to_s }).to include('where is OpenGoal implemented?')
      expect(seen.map { |m| m[:content].to_s }).to include('lib/pwn/ai/agent/open_goal.rb')
      expect(seen.map { |m| m[:content].to_s }).to include('where is this logic implemented in /opt/pwn when using pwn-ai')
    ensure
      FileUtils.rm_rf(sess_tmp) if sess_tmp
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

    it 'does not refuse sweeps for missing scope language' do
      expect(described_class).not_to respond_to(:recon_authorized?)
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).not_to match(/AUTH_SCOPE_RX/)
      expect(src).not_to match(/need scope language/)
      expect(src).not_to match(/refuse the live scan/)
      expect(src).not_to match(/pwn_recon_authorized/)
      expect(src).not_to match(/in-scope authorization/)
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
      expect(src).to match(/if intent == :howto.*?txt = answer_howto/m)
    end

    it 'run short-circuits pure recall via answer_recall before plan_first' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/RECALL_RX/)
      expect(src).to match(/answer_recall/)
      expect(src).to match(/intent == :recall.*?txt = answer_recall/m)
      expect(src).to match(/skip_plan/)
      expect(src).not_to match(/request_kind/)
    end

    it 'run short-circuits greetings via answer_greeting before plan_first' do
      src = File.read(described_class.method(:run).source_location.first)
      expect(src).to match(/GREETING_RX/)
      expect(src).to match(/answer_greeting/)
      expect(src).to match(/intent == :greeting.*?txt = answer_greeting/m)
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

    it 'answer_recall looks up the previous session file for last-session asks' do
      sess_tmp = Dir.mktmpdir('pwn-sess-last')
      stub_const('PWN::Sessions::SESSIONS_DIR', sess_tmp)
      old = PWN::Sessions.create(id: '20200101_000000_oldone', title: 'old')
      PWN::Sessions.append(session_id: old[:id], role: 'user', content: 'SHIP MARKER LAST SESSION')
      PWN::Sessions.append(session_id: old[:id], role: 'assistant', content: 'ack old')
      cur = PWN::Sessions.create(id: '20260101_000000_curone', title: 'current')
      PWN::Sessions.append(session_id: cur[:id], role: 'user', content: 'what did I just say?')
      PWN::Sessions.append(session_id: cur[:id], role: 'assistant', content: "You just said:\n\nwhat did I just say?")
      allow(described_class).to receive(:should_auto_introspect?).and_return(false)
      req = 'what did I just say in the last session?'
      expect(described_class.request_intent(request: req)).to eq(:recall)
      out = described_class.send(
        :answer_recall,
        request: req,
        session_id: cur[:id],
        system_role_content: 'test'
      )
      expect(out).to include('SHIP MARKER LAST SESSION')
      expect(out).not_to match(/You just said:\s*\n\s*what did I just say\?/i)
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

  it 'streams request-processing progress through PWN::Plugins::Log when debug is on' do
    src = File.read(described_class.method(:run).source_location.first)
    expect(src).to match(/PWN::Plugins::Log\.start_debug/)
    expect(src).to match(/next_request_log!/)
    expect(src).to match(/finish_request_log!/)
    expect(src).to match(/skip_roll|user_path\?/)
    expect(src).to match(/bounce /)
    expect(src).to match(/plan_first=/)
    expect(src).to match(/final text/)
    expect(src).to match(/debug_tools_line|tools=.*\[/)
    expect(src).to match(/debug_msgs_line|msgs=.*\[/)
    expect(src).to match(/PWN::Plugins::Log\.progress/)
    expect(src).to match(/quiet_debug_tui!/)
    expect(described_class).to respond_to(:debug_on?)
  end
end # rubocop:enable Metrics/BlockLength
