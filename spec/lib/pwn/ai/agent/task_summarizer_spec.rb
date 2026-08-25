# frozen_string_literal: true

# rubocop:disable Metrics/BlockLength

require 'spec_helper'

describe PWN::AI::Agent::TaskSummarizer do
  it 'fresh method should exist' do
    expect(described_class).to respond_to :fresh
  end

  it 'record! method should exist' do
    expect(described_class).to respond_to :record!
  end

  it 'emit! method should exist' do
    expect(described_class).to respond_to :emit!
  end

  it 'flush! method should exist' do
    expect(described_class).to respond_to :flush!
  end

  it 'enabled? method should exist' do
    expect(described_class).to respond_to :enabled?
  end

  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'about_to method should exist' do
    expect(described_class).to respond_to :about_to
  end

  it 'plan method should exist' do
    expect(described_class).to respond_to :plan
  end

  it 'emit_plan! method should exist' do
    expect(described_class).to respond_to :emit_plan!
  end

  it 'active_task / plan_context / active_task_prompt methods should exist' do
    expect(described_class).to respond_to :active_task
    expect(described_class).to respond_to :plan_context
    expect(described_class).to respond_to :active_task_prompt
    expect(described_class).to respond_to :relevance_query
    expect(described_class).to respond_to :tool_jargon_task?
    expect(described_class).to respond_to :plan_open?
    expect(described_class).to respond_to :unfinished_tasks
  end

  it 'format_plan method should exist' do
    expect(described_class).to respond_to :format_plan
  end

  it 'llm_plan_enabled? method should exist' do
    expect(described_class).to respond_to :llm_plan_enabled?
  end

  it 'declares every method via def self.<name> (no bare def / module_function)' do
    src = File.read(described_class.method(:plan).source_location.first)
    expect(src).not_to match(/^\s*module_function\b/)
    expect(src).not_to match(/^\s*def (?!self\.)/)
    expect(src).to match(/public_class_method def self\.plan/)
    expect(src).to match(/public_class_method def self\.about_to/)
    expect(src).to match(/private_class_method def self\./)
  end

  describe 'executive high-level brief (one-to-many)' do
    let(:goal) { 'ship plain-English task briefs to executive management' }
    let(:state) { described_class.fresh(request: goal) }

    before do
      # Keep about_to / record! paths offline and deterministic.
      allow(PWN::Env).to receive(:dig).and_call_original
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_llm).and_return(false)
    end

    it 'summarizes a whole tool collection without dumping raw commands' do
      line = described_class.about_to(
        tools: [
          { name: 'shell', args: { 'command' => 'cat /opt/pwn/spec/lib/pwn/ai/agent/task_summarizer_spec.rb' } },
          { name: 'pwn_eval', args: { 'code' => '1+1' } }
        ],
        state: state
      )
      expect(line).to be_a(String)
      # English task is primary (task k/n or toward:); tools are via suffix
      expect(line).to match(%r{task \d+/|toward:|Next:}i)
      expect(line).to include('shell')
      expect(line).to include('pwn_eval')
      # Intent makes the batch distinctive (read vs edit vs search)
      expect(line).to match(/read|eval-ruby/i)
      # No low-level command / path dump in the task brief
      expect(line).not_to include('cat /opt/pwn')
      expect(line).not_to include('task_summarizer_spec')
      expect(line).not_to include('1+1')
      expect(line).not_to match(/about to run shell:/i)
    end

    it 'does not label a TransparentBrowser navigate as apply code/host changes' do
      line = described_class.about_to(
        tools: [
          {
            name: 'pwn_eval',
            args: {
              'code' => "$browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :chrome); $browser.goto('https://example.com')"
            }
          }
        ],
        state: state,
        request: 'Navigate to https://example.com and list blog URLs'
      )
      expect(line).to be_a(String)
      expect(line).not_to match(%r{apply code/host changes}i)
      expect(line).to match(/navigate|collect|browse|page/i)
    end

    it 'advances off a Navigate task after one successful browse eval' do
      st = described_class.fresh(request: 'Navigate to https://example.com and list posts')
      st[:plan] = [
        'Understand the request',
        'Navigate to the example.com website',
        'Collect every blog post URL',
        'Close the browser'
      ]
      st[:plan_idx] = 1
      described_class.record!(
        state: st,
        name: 'pwn_eval',
        args: { 'code' => "browser.goto('https://example.com')" },
        result: '{"success":true,"result":{"value":"{url: \\"https://example.com/\\"}"},"effect":"browse"}'
      )
      expect(st[:plan_idx]).to be > 1
    end

    it 'keeps single-tool legacy about_to(name:, args:) as a high-level brief' do
      line = described_class.about_to(
        name: 'shell',
        args: { 'command' => 'rg TaskSummarizer /opt/pwn' },
        state: state
      )
      expect(line).to match(%r{task \d+/|Next:|toward:}i)
      expect(line).to include('shell')
      expect(line).to match(/search/i)
      expect(line).not_to include('rg TaskSummarizer')
    end

    it 'emits distinctive briefs when tool mix or intent changes (no clones)' do
      a = described_class.about_to(
        tools: [{ name: 'shell', args: { 'command' => 'rg TaskSummarizer /opt/pwn' } }],
        state: state
      )
      b = described_class.about_to(
        tools: [{ name: 'pwn_eval', args: { 'code' => '1+1' } }],
        state: state
      )
      c = described_class.about_to(
        tools: [{ name: 'shell', args: { 'command' => 'sed -i s/x/y/ file.rb' } }],
        state: state
      )
      expect(a).to be_a(String)
      expect(b).to be_a(String)
      expect(c).to be_a(String)
      expect(a).not_to eq(b)
      expect(a).not_to eq(c)
      expect(b).not_to eq(c)
      expect(a).to match(/search/i)
      expect(c).to match(/edit/i)
    end

    it 'suppresses duplicate identical batch briefs' do
      tools = [{ name: 'shell', args: { 'command' => 'ls' } }]
      first = described_class.about_to(tools: tools, state: state)
      second = described_class.about_to(tools: tools, state: state)
      expect(first).to be_a(String)
      expect(second).to be_nil
    end

    it 'record! stays free of tool-result spam (advancement brief ok)' do
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_every).and_return(1)
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_interval_s).and_return(9_999)
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary).and_return(true)
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_verbose).and_return(false)

      described_class.about_to(tools: [{ name: 'shell' }], state: state)
      line = described_class.record!(state: state, name: 'shell', args: 'rake', result: '{success:true}')
      # May emit English advancement when plan_idx moves; never embeds tool results.
      if line
        expect(line).to match(/task \d+|Advanced/i)
        expect(line).not_to include('{success:true}')
        expect(line).not_to include('rake')
      end
      expect(state[:total]).to eq 1
    end

    it 'flush! closes with a plain-English done brief (still no raw result)' do
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_verbose).and_return(false)

      described_class.about_to(tools: [{ name: 'shell' }, { name: 'shell' }], state: state)
      described_class.record!(state: state, name: 'shell', args: 'rake', result: '{success:true}')
      described_class.record!(state: state, name: 'shell', args: 'rake 2>&1', result: '{success:true}')
      fin = described_class.flush!(state: state)
      expect(fin).to be_a(String)
      expect(fin).to match(/Finished/i)
      expect(fin).to include('2 tool')
      expect(fin).to include('shell')
      expect(fin).not_to include('{success:true}')
      expect(fin).not_to include('rake 2>&1')
      # Full goal is retained (no 60-char ellipsis)
      expect(fin).to include(goal)
    end

    it 'verbose progress may emit mid-flight but never embeds tool results' do
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_every).and_return(2)
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_interval_s).and_return(9_999)
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary).and_return(true)
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_verbose).and_return(true)

      expect(described_class.record!(state: state, name: 'shell', args: 'rake', result: '{success:true}')).to be_nil
      line = described_class.record!(state: state, name: 'memory_recall', args: 'task', result: '{success:true}')
      expect(line).to be_a(String)
      expect(line).to match(/Progress/i)
      expect(line).not_to include('{success:true}')
    end
  end

  describe 'full task summary + tangible-task plan on submit' do
    let(:request) do
      'TaskSummarizer needs improvement. 1. the task summary in its entirety should be displayed in pwn-ai 2. once a request is submitted by a user, the request should be broken down into a list of tangible tasks'
    end
    let(:state) { described_class.fresh(request: request) }

    it 'plan breaks a user request into an ordered list of tangible tasks' do
      tasks = described_class.plan(request: request, state: state)
      expect(tasks).to be_a(Array)
      expect(tasks.length).to be >= 2
      expect(state[:plan]).to eq tasks
      joined = tasks.join(' | ').downcase
      expect(joined).to match(/display|entire|summary|truncat|full/)
      expect(joined).to match(/break|tangible|decompos|list/)
    end

    it 'format_plan / emit_plan! return the full multi-line summary (no 280-char cut)' do
      described_class.plan(request: request, state: state)
      text = described_class.emit_plan!(state: state)
      expect(text).to be_a(String)
      expect(text).to include('Goal:')
      expect(text).to include('Tangible tasks')
      expect(text).to match(%r{task 1/\d+:})
      expect(text).to match(%r{task 2/\d+:})
      expect(text).to include("\n")
      # Entire request goal retained — not hard-truncated to PREVIEW_LEN/280
      expect(text.length).to be > 120
      expect(text).not_to match(/…\z/)
      expect(state[:plan_emitted]).to eq true
      expect(state[:plan_text]).to eq text
      # Idempotent
      expect(described_class.emit_plan!(state: state)).to eq text
    end

    it 'about_to does not ellipsize long briefs and shows full plan text' do
      long_goal = "improve task summarizer end-to-end: #{'x' * 400}"
      st = described_class.fresh(request: long_goal)
      described_class.plan(
        request: long_goal,
        state: st,
        llm_tasks: [
          'read the current TaskSummarizer implementation',
          'implement the end-to-end improvements',
          'verify with specs and report completion'
        ]
      )
      plan_text = described_class.emit_plan!(state: st)
      expect(plan_text.length).to be > 280
      expect(plan_text).to include(long_goal)
      expect(plan_text).not_to include('…')
      line = described_class.about_to(tools: [{ name: 'shell' }, { name: 'pwn_eval' }], state: st)
      expect(line).to be_a(String)
      expect(line).to match(%r{task \d+/\d+:}i)
      expect(line).not_to include('…')
      # Mid-flight brief stays distinctive; full goal lives on the plan line
      expect(line).to include('shell')
    end

    it 'enumerates explicit numbered steps from the request' do
      req = 'Do three things. 1. locate the file 2. patch the truncation 3. add plan on submit'
      tasks = described_class.plan(request: req)
      expect(tasks.length).to be >= 3
      expect(tasks[0].downcase).to include('locate')
      expect(tasks[1].downcase).to match(/patch|truncat/)
      expect(tasks[2].downcase).to match(/plan|submit/)
    end
  end

  describe 'LLM-backed plan generation for any request' do
    let(:subnet_req) do
      'tell me about the hosts on this subnet and display them in JSON format'
    end

    let(:llm_subnet_json) do
      [
        'determine what subnet this host is on',
        'discover which hosts respond on the local subnet',
        'probe common services on live hosts',
        'aggregate the list of live hosts',
        'present the live hosts as valid JSON'
      ].to_json
    end

    it 'asks the LLM (via chat_for_plan) and parses a JSON task array for arbitrary goals' do
      expect(described_class).to receive(:chat_for_plan).with(request: subnet_req).and_return(llm_subnet_json)
      state = described_class.fresh(request: subnet_req)
      tasks = described_class.plan(request: subnet_req, state: state)
      expect(tasks).to be_a(Array)
      expect(tasks.length).to be >= 5
      expect(state[:plan_source]).to eq :llm
      joined = tasks.join(' | ').downcase
      expect(joined).to match(/subnet/)
      expect(joined).to match(/host/)
      expect(joined).to match(/json/)
      expect(tasks.none? { |t| t.match?(/Execute the request:/i) }).to eq true
    end

    it 'parse_llm_tasks accepts fenced JSON, plain arrays, and numbered lists' do
      fenced = "```json\n#{llm_subnet_json}\n```"
      expect(described_class.parse_llm_tasks(raw: fenced).length).to be >= 5

      numbered = "1. find the Target\n2. gather evidence\n3. write the report"
      parsed = described_class.parse_llm_tasks(raw: numbered)
      expect(parsed.length).to eq 3
      expect(parsed[0].downcase).to include('target')
    end

    it 'works for non-network goals without static domain matchers' do
      req = 'refactor the authentication middleware and add unit tests'
      llm = [
        'locate the authentication middleware source',
        'refactor the middleware for clarity and safety',
        'add unit tests covering the new behavior',
        'run the test suite and report completion'
      ].to_json
      expect(described_class).to receive(:chat_for_plan).with(request: req).and_return(llm)
      tasks = described_class.plan(request: req)
      joined = tasks.join(' | ').downcase
      expect(joined).to match(/auth/)
      expect(joined).to match(/refactor|middleware/)
      expect(joined).to match(/test/)
    end

    it 'emit_plan! labels LLM steps as task k/n' do
      expect(described_class).to receive(:chat_for_plan).with(request: subnet_req).and_return(llm_subnet_json)
      state = described_class.fresh(request: subnet_req)
      text = described_class.emit_plan!(state: state)
      n = state[:plan].length
      expect(n).to be >= 5
      expect(text).to include('Goal:')
      expect(text).to include(subnet_req)
      expect(text).to include("task 1/#{n}:")
      expect(text).to include("task #{n}/#{n}:")
      expect(text.downcase).to match(/json/)
      expect(state[:plan_source]).to eq :llm
    end

    it 'about_to keeps task k/n without restating the full goal every batch' do
      expect(described_class).to receive(:chat_for_plan).with(request: subnet_req).and_return(llm_subnet_json)
      state = described_class.fresh(request: subnet_req)
      plan_text = described_class.emit_plan!(state: state)
      expect(plan_text).to match(%r{task 1/\d+:})

      first = described_class.about_to(
        tools: [{ name: 'shell', args: { 'command' => 'ip -4 route; ip -4 addr' } }],
        state: state
      )
      expect(first).to be_a(String)
      # English-task-as-primary: first batch ALSO shows task k/n (not tool jargon first)
      expect(first).to match(%r{task 1/\d+:}i)
      expect(first).to match(/via |shell/i)
      expect(first).not_to include(subnet_req)

      # Search-only tools must NOT consume the English plan. A later batch
      # with a different tool still restates task k/n, never the full goal.
      3.times do |i|
        described_class.record!(state: state, name: 'shell', args: "probe #{i}", result: '{success:true}')
      end
      expect(state[:plan_idx]).to eq 0

      second = described_class.about_to(
        tools: [{ name: 'pwn_eval', args: { 'code' => '1+1' } }],
        state: state
      )
      expect(second).to be_a(String)
      expect(second).to match(%r{task \d+/\d+:}i)
      expect(second).not_to include(subnet_req)
    end

    it 'how-to questions still get a task compass — there is no request type' do
      allow(PWN::Env).to receive(:dig).and_call_original
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_llm).and_return(false)
      req = 'how to do a ping sweep of a subnet using hping3?'
      expect(described_class.needs_task_breakdown?(request: req)).to eq(true)
      expect(described_class).not_to respond_to :request_kind
      expect(described_class.plan(request: 'what color is a cherry')).to eq([])
    end

    it 'falls back generically when LLM is disabled (no static domain scripts)' do
      allow(PWN::Env).to receive(:dig).and_call_original
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_llm).and_return(false)
      # Must NOT call the LLM path.
      expect(described_class).not_to receive(:chat_for_plan)
      tasks = described_class.plan(request: subnet_req)
      expect(tasks).to be_a(Array)
      expect(tasks.length).to be >= 2
      joined = tasks.join(' | ').downcase
      # Generic fallback — understand + core work + present JSON — NOT ARP/ICMP canned list.
      expect(joined).to match(/json|present|core work|understand|carry out/)
      expect(described_class.heuristic_decompose(goal: subnet_req)).to eq(
        described_class.fallback_decompose(goal: subnet_req)
      )
    end

    it 'splits analyze-plus-artifact goals instead of pasting the full request twice' do
      goal = 'Exhaustively analyze the running application for vulnerabilities. ' \
             'Once complete, generate a complete PDF report and store in /tmp/container_pentest-p4.pdf'
      tasks = described_class.fallback_decompose(goal: goal)
      expect(tasks.length).to be >= 2
      expect(tasks.join("\n")).to include('/tmp/container_pentest-p4.pdf')
      expect(tasks.grep(/Understand the request:/).length).to eq(0)
      expect(tasks.grep(/Carry out the core work for:/).length).to eq(0)
    end

    it 'accepts injected :tasks / :llm_tasks without network I/O' do
      custom = ['step alpha', 'step beta', 'verify completion']
      tasks = described_class.plan(request: 'anything at all', tasks: custom)
      expect(tasks.first(3)).to eq custom

      tasks2 = described_class.plan(
        request: 'another request',
        llm_tasks: ['discover scope', 'do the work', 'deliver results']
      )
      expect(tasks2.join(' | ').downcase).to match(/discover|work|deliver|verif/)
    end

    it 'source tree has no static per-domain decompose_* planners' do
      src = File.read(described_class.method(:plan).source_location.first)
      expect(src).not_to match(/def self\.decompose_subnet_host_recon/)
      expect(src).not_to match(/def self\.decompose_by_domain/)
      expect(src).not_to match(/def self\.subnet_host_recon\?/)
      expect(src).to match(/def self\.llm_decompose/)
      expect(src).to match(/def self\.chat_for_plan/)
      expect(src).to match(/PLAN_SYSTEM/)
    end

    it 'keeps code-improvement plans working via LLM (non-network regression)' do
      req = 'find the TaskSummarizer and fix the truncation bug then run rspec'
      llm = [
        'locate the TaskSummarizer source and call sites',
        'fix the truncation bug in the implementation',
        'run rspec to verify the fix'
      ].to_json
      expect(described_class).to receive(:chat_for_plan).with(request: req).and_return(llm)
      tasks = described_class.plan(request: req)
      joined = tasks.join(' | ').downcase
      expect(joined).to match(/locat|source|find/)
      expect(joined).to match(/fix|truncat/)
      expect(joined).to match(/spec|rspec|verif/)
    end
  end

  describe 'English-task-as-primary + advancement' do
    let(:goal) { 'locate the source, fix the bug, then run rspec' }
    let(:state) do
      st = described_class.fresh(request: goal)
      st[:plan] = [
        'locate the TaskSummarizer source',
        'fix the truncation bug',
        'run rspec to verify'
      ]
      st[:plan_idx] = 0
      st[:plan_emitted] = true
      st
    end

    it 'about_to leads with task k/n English text; tools are via suffix' do
      line = described_class.about_to(
        tools: [{ name: 'shell', args: { 'command' => 'rg TaskSummarizer lib' } }],
        state: state
      )
      expect(line).to be_a(String)
      expect(line).to start_with('task 1/3:')
      expect(line).to include('locate the TaskSummarizer source')
      expect(line).to match(/via shell/i)
      expect(line).to match(/search/i)
      # Not tool-jargon-first
      expect(line).not_to match(/\ANext:/i)
    end

    it 'active_task / plan_context / active_task_prompt expose English focus' do
      info = described_class.active_task(state: state)
      expect(info[:idx]).to eq 0
      expect(info[:label]).to include('task 1/3:')
      expect(info[:item]).to include('locate')

      ctx = described_class.plan_context(state: state)
      expect(ctx).to include('advisory compass')
      expect(ctx).not_to include('SOLE driver')
      expect(ctx).to include('▶ task 1/3:')
      expect(ctx).to include('task 2/3:')
      expect(ctx).to include("Original request (immutable): #{goal}")

      first = described_class.active_task_prompt(state: state, force: true)
      expect(first).to include('Active:')
      expect(first).to include('task 1/3:')
      expect(first).to include("Original request (immutable): #{goal}")
      # second call same idx → nil (no spam)
      expect(described_class.active_task_prompt(state: state)).to be_nil

      state[:plan_idx] = 1
      nxt = described_class.active_task_prompt(state: state)
      expect(nxt).to match(%r{Compass: task 2/3:}i)
      expect(nxt).to include("Original request (immutable): #{goal}")
    end

    it 'record! does not treat two successful searches as finishing the whole plan' do
      line = nil
      2.times do
        line = described_class.record!(
          state: state,
          name: 'shell',
          args: { 'command' => 'rg TaskSummarizer lib' },
          result: '{"success":true,"result":{"stdout":"hit","exit":0}}'
        )
      end
      expect(state[:plan_idx]).to be < (state[:plan].length - 1)
      expect(described_class.plan_open?(state: state)).to eq true
      leftover = described_class.unfinished_tasks(state: state).map { |t| t[:idx] }
      expect(leftover).to include(2)
    end

    it 'two ls/find calls do not skip to the last English task' do
      described_class.active_task_prompt(state: state, force: true)
      briefs = [
        'ls /opt/pwn/lib/pwn/ai/agent',
        'find /opt/pwn/lib -name task_summarizer.rb'
      ].map do |cmd|
        described_class.record!(
          state: state,
          name: 'shell',
          args: { 'command' => cmd },
          result: '{"success":true,"result":{"stdout":"task_summarizer.rb","exit":0}}'
        )
      end

      expect(state[:plan_idx]).to be < (state[:plan].length - 1)
      expect(briefs.join).not_to match(/Completed task/i)

      info = described_class.active_task(state: state)
      leftover = described_class.unfinished_tasks(state: state).map { |t| t[:idx] }
      expect(described_class.plan_open?(state: state)).to eq true
      expect(leftover).to include(2)
      # Covered locate must not keep focus on task 1 while later work is open.
      expect(info[:idx]).to eq(leftover.min)
      expect(info[:idx]).not_to eq(state[:plan].length - 1)
    end

    it 'active_task_prompt stays quiet once every English task is covered' do
      st = described_class.fresh(request: 'what is my hostname?')
      st[:plan] = [
        'Determine the local hostname',
        'Present the result and report completion'
      ]
      st[:plan_idx] = 0
      st[:plan_emitted] = true
      described_class.record!(
        state: st,
        name: 'shell',
        args: { 'command' => 'hostname' },
        result: '{"success":true,"result":{"stdout":"kali-box","exit":0}}'
      )
      expect(described_class.plan_open?(state: st)).to eq false
      expect(described_class.active_task_prompt(state: st, force: true)).to be_nil
    end

    it 'record! emits advancement brief only on real handoff to the next English task' do
      described_class.record!(
        state: state,
        name: 'shell',
        args: { 'command' => 'rg TaskSummarizer lib' },
        result: '{"success":true,"result":{"stdout":"lib/pwn/ai/agent/task_summarizer.rb","exit":0}}'
      )
      line = described_class.record!(
        state: state,
        name: 'shell',
        args: { 'command' => 'sed -i s/truncation/fixed/ lib/pwn/ai/agent/task_summarizer.rb' },
        result: '{"success":true,"result":{"stdout":"patched task_summarizer.rb","exit":0}}'
      )
      expect(state[:plan_idx]).to eq 1
      expect(line).to be_a(String)
      expect(line).to match(%r{Advanced past task 1/3}i)
      expect(line).to match(%r{now task 2/3:}i)
      expect(line).to include('fix the truncation bug')
    end
  end

  describe 'RL-adjacent executive contracts' do
    let(:goal) { 'locate the source, fix the bug, then run rspec' }
    let(:state) do
      st = described_class.fresh(request: goal)
      st[:plan] = [
        'locate the TaskSummarizer source',
        'fix the truncation bug',
        'run rspec to verify'
      ]
      st[:plan_idx] = 0
      st
    end

    it 'honors plan_idx=0 in active_plan_index (no total-bucket skip)' do
      # force total high enough that a bucket heuristic would skip past 0
      state[:total] = 12
      expect(state).to have_key(:plan_idx)
      expect(state[:plan_idx]).to eq 0
      idx = described_class.send(:active_plan_index, state: state)
      expect(idx).to eq 0
    end

    it 'unify_plan! rewrites state[:plan] from a surviving outline' do
      outline = <<~OUT
        1. discover the local IPv4 subnet
        2. probe live hosts via ARP then ICMP
        3. present live hosts as JSON
        p(success)=0.7
      OUT
      tasks = described_class.unify_plan!(state: state, outline: outline, source: :plan_first)
      expect(tasks.length).to be >= 3
      expect(state[:plan].first.downcase).to match(/subnet|discover|ipv4/)
      expect(state[:plan_source]).to eq :plan_first
      expect(state[:unified_from]).to include('subnet')
      # plan_idx still honored at 0 after unify
      expect(state[:plan_idx]).to eq 0
      # English rewrite also refreshes plan_text for TUI parity
      state[:plan_emitted] = true
      described_class.unify_plan!(state: state, outline: outline, source: :plan_first)
      expect(state[:plan_text]).to include('Tangible tasks')
      expect(state[:plan_text]).to match(/discover the local/i)
    end

    it 'unify_plan! refuses plan_first tool-jargon outlines so English tasks stay sole driver' do
      original = state[:plan].dup
      jargon = <<~OUT
        1. `shell`
        2. `pwn_eval`
        3. `shell` / `pwn_eval`
        4. learning_note_outcome
        5. assistant_answer
        p(success)=0.7
      OUT
      kept = described_class.unify_plan!(state: state, outline: jargon, source: :plan_first)
      expect(kept).to eq original
      expect(state[:plan]).to eq original
      expect(state[:plan_source]).to eq :kept_english
      expect(state[:unified_from]).to include('shell')
      # No tool-name items leaked into plan
      expect(state[:plan].none? { |t| described_class.tool_jargon_task?(item: t) }).to eq true
    end

    it 'tool_jargon_task? detects bare/backticked tool tokens and not English prose' do
      expect(described_class.tool_jargon_task?(item: '`shell`')).to eq true
      expect(described_class.tool_jargon_task?(item: 'shell')).to eq true
      expect(described_class.tool_jargon_task?(item: 'pwn_eval / shell')).to eq true
      expect(described_class.tool_jargon_task?(item: 'learning_note_outcome')).to eq true
      expect(described_class.tool_jargon_task?(item: 'locate the TaskSummarizer source')).to eq false
      expect(described_class.tool_jargon_task?(item: 'fix the truncation bug')).to eq false
    end

    it 'relevance_query prefers active English task + plan over bare request' do
      q = described_class.relevance_query(state: state, request: state[:request])
      expect(q).to include('locate the TaskSummarizer source')
      expect(q).to include('fix the truncation bug')
      expect(q).to include('run rspec to verify')
    end

    it 'apply_prm_advancement! holds on +1 search streak and on -1; advances on next-task handoff' do
      described_class.apply_prm_advancement!(
        state: state,
        rewards: [1],
        intents: ['search'],
        names: ['shell']
      )
      expect(state[:plan_idx]).to eq 0
      expect(state[:last_prm_signal].to_s).to match(/hold|streak/)

      described_class.apply_prm_advancement!(
        state: state,
        rewards: [1],
        intents: %w[search read],
        names: ['shell']
      )
      # Two successful searches must NOT complete "locate the source".
      expect(state[:plan_idx]).to eq 0

      state[:tools_on_task] = 2
      described_class.apply_prm_advancement!(
        state: state,
        rewards: [1],
        intents: ['edit'],
        names: ['shell'],
        result: 'patched task_summarizer.rb'
      )
      expect(state[:plan_idx]).to eq 1
      expect(state[:last_prm_signal].to_s).to match(/advance/)

      hold_idx = state[:plan_idx]
      described_class.apply_prm_advancement!(
        state: state,
        rewards: [1, -1],
        intents: ['edit'],
        names: ['shell'],
        mistake: false
      )
      expect(state[:plan_idx]).to eq hold_idx
      expect(state[:last_prm_signal]).to eq :hold_regress

      described_class.apply_prm_advancement!(
        state: state,
        rewards: [1, 1],
        intents: ['edit'],
        names: ['pwn_eval'],
        mistake: true
      )
      expect(state[:plan_idx]).to eq hold_idx
      expect(state[:last_prm_signal]).to eq :hold_regress
    end

    it 'chat_for_plan source never nests Loop.run (uses Reflect.on / engine_chat only)' do
      src = File.read(described_class.method(:chat_for_plan).source_location.first)
      # Extract chat_for_plan body region roughly
      body = src[/public_class_method def self\.chat_for_plan.*?public_class_method def self\.\w+/m]
      body ||= src
      expect(body).not_to match(/Loop\.run\b/)
      expect(src).to match(/Reflect\.on\b/)
      expect(src).to match(/engine_chat\b/)
      expect(src).to match(/pwn_reflect_depth|reflect_available\?/)
    end

    it 'record! feeds R2-local advancement without stuffing Reward into briefs' do
      state[:plan_idx] = 0
      2.times do
        described_class.record!(
          state: state,
          name: 'shell',
          args: { 'command' => 'rg TaskSummarizer lib' },
          result: '{"success":true,"result":{"stdout":"hit","exit":0}}'
        )
      end
      # either PRM streak or heuristic may advance; must not go backward
      expect(state[:plan_idx]).to be >= 0
      expect(state[:last_prm_signal]).not_to be_nil
    end
  end

  describe 'task compass (no request type)' do
    before do
      allow(PWN::Env).to receive(:dig).and_call_original
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_llm).and_return(false)
    end

    it 'has no request_kind classifier' do
      expect(described_class).not_to respond_to :request_kind
      expect(described_class).not_to respond_to :heuristic_request_kind
      expect(described_class).not_to respond_to :parse_kind_label
      expect(described_class).not_to respond_to :chat_for_kind
      expect(described_class).to respond_to :needs_task_breakdown?
      expect(described_class.needs_task_breakdown?(request: 'anything')).to eq(true)
    end

    it 'fresh state has no request_kind and format_plan has no Request type line' do
      req = 'refactor the authentication middleware and add unit tests'
      st = described_class.fresh(request: req)
      expect(st).not_to have_key(:request_kind)
      steps = [
        'locate the authentication middleware source',
        'refactor the middleware for clarity and safety',
        'add unit tests covering the new behavior',
        'run the test suite and report completion'
      ]
      tasks = described_class.plan(request: req, state: st, tasks: steps)
      expect(tasks.length).to be >= 3
      text = described_class.format_plan(tasks: tasks, request: req)
      expect(text).not_to match(/Request type/)
      expect(text).to match(/Tangible tasks/)
      expect(text).to match(%r{task 1/\d+:})
    end

    it 'plan_open? stays true until mutate and verify English tasks have evidence' do
      st = described_class.fresh(request: 'locate, fix, verify')
      st[:plan] = [
        'locate the TaskSummarizer source',
        'fix the truncation bug',
        'run rspec to verify'
      ]
      st[:plan_idx] = 0
      expect(described_class.plan_open?(state: st)).to eq true

      described_class.record!(
        state: st,
        name: 'shell',
        args: { 'command' => 'rg TaskSummarizer lib' },
        result: '{"success":true,"result":{"stdout":"lib/pwn/ai/agent/task_summarizer.rb","exit":0}}'
      )
      expect(described_class.plan_open?(state: st)).to eq true
      expect(described_class.unfinished_tasks(state: st).map { |t| t[:idx] }).to include(1, 2)

      described_class.record!(
        state: st,
        name: 'shell',
        args: { 'command' => 'sed -i s/bug/fix/ lib/pwn/ai/agent/task_summarizer.rb' },
        result: '{"success":true,"result":{"stdout":"patched task_summarizer.rb","exit":0}}'
      )
      open_idx = described_class.unfinished_tasks(state: st).map { |t| t[:idx] }
      expect(open_idx).to include(2)
      expect(open_idx).not_to include(1)
      expect(described_class.plan_open?(state: st)).to eq true

      described_class.record!(
        state: st,
        name: 'shell',
        args: { 'command' => 'bundle exec rspec spec/lib/pwn/ai/agent/task_summarizer_spec.rb' },
        result: '{"success":true,"result":{"stdout":"12 examples, 0 failures","exit":0}}'
      )
      expect(described_class.plan_open?(state: st)).to eq false
      expect(described_class.unfinished_tasks(state: st)).to eq([])
    end

    it 'task_phase classifies English stems (locate/verify/change), not only exact \b-words' do
      expect(described_class.send(:task_phase, item: 'locate the TaskSummarizer source')).to eq(:discover)
      expect(described_class.send(:task_phase, item: 'identify where tasks are skipped')).to eq(:discover)
      expect(described_class.send(:task_phase, item: 'Determine the local hostname')).to eq(:discover)
      expect(described_class.send(:task_phase, item: 'change the advancement logic')).to eq(:mutate)
      expect(described_class.send(:task_phase, item: 'improve completion handling')).to eq(:mutate)
      expect(described_class.send(:task_phase, item: 'Refactor Loop.run')).to eq(:mutate)
      expect(described_class.send(:task_phase, item: 'Verify the result and report completion')).to eq(:present)
      expect(described_class.send(:task_phase, item: 'Present the result and report completion')).to eq(:present)
      expect(described_class.send(:task_phase, item: 'Verify full task completion end-to-end')).to eq(:verify)
      expect(described_class.send(:task_phase, item: 'run rspec to verify')).to eq(:verify)
    end

    it 'host-evidence plans close after a live lookup (forced closer is not a test-runner verify)' do
      st = described_class.fresh(request: 'what is my hostname?')
      closer = described_class.send(
        :normalize_task_list,
        tasks: ['Determine the local hostname'],
        goal: 'what is my hostname?'
      )
      expect(closer.join(' ')).not_to match(/\brspec\b|\brubocop\b/)
      expect(described_class.send(:task_phase, item: closer.last)).not_to eq(:verify)
      st[:plan] = closer
      st[:plan_idx] = 0
      described_class.record!(
        state: st,
        name: 'shell',
        args: { 'command' => 'hostname' },
        result: '{"success":true,"result":{"stdout":"kali-box","exit":0}}'
      )
      expect(described_class.plan_open?(state: st)).to eq false
      expect(described_class.unfinished_tasks(state: st)).to eq([])
    end

    it 'three on-task discover tools advance one English task and do not jump to the last' do
      st = described_class.fresh(request: 'map then fix then verify')
      st[:plan] = [
        'locate the TaskSummarizer source',
        'identify where planned tasks are skipped',
        'Implement the completion fix',
        'Verify full task completion end-to-end'
      ]
      st[:plan_idx] = 0
      3.times do |i|
        described_class.record!(
          state: st,
          name: 'shell',
          args: { 'command' => "rg TaskSummarizer lib #{i}" },
          result: '{"success":true,"result":{"stdout":"lib/pwn/ai/agent/task_summarizer.rb","exit":0}}'
        )
      end
      expect(st[:plan_idx]).to eq 1
      expect(st[:plan_idx]).to be < (st[:plan].length - 1)
      expect(described_class.plan_open?(state: st)).to eq true
    end

    it 'a verify task is covered after the verifier ran, even with remaining offenses' do
      st = described_class.fresh(request: 'run rubocop')
      st[:plan] = [
        'Refactor Loop.run',
        'run rubocop to verify'
      ]
      st[:plan_idx] = 1
      described_class.record!(
        state: st,
        name: 'shell',
        args: { 'command' => 'bundle exec rubocop lib/pwn/ai/agent/loop.rb' },
        result: '{"success":true,"result":{"stdout":"4 offenses detected","exit":1}}'
      )
      leftover = described_class.unfinished_tasks(state: st).map { |t| t[:idx] }
      expect(leftover).not_to include(1)
    end

    it 'five successful ls/find shells never skip a 5-step mapping plan to the last task' do
      st = described_class.fresh(request: 'map then fix autonomous_goal completion')
      st[:plan] = [
        'Map how autonomous_goal plans, tracks, and completes work units',
        'Identify where and why planned tasks are skipped',
        'Determine the root cause of premature finalized responses',
        'Implement fixes so every planned task is finished',
        'Verify full task completion end-to-end'
      ]
      st[:plan_idx] = 0
      st[:plan_emitted] = true
      5.times do |i|
        described_class.record!(
          state: st,
          name: 'shell',
          args: { 'command' => "ls /opt/pwn && find lib -name '*#{i}*'" },
          result: '{"success":true,"result":{"stdout":"/opt/pwn","exit":0}}'
        )
      end
      expect(st[:plan_idx]).to be < (st[:plan].length - 1)
      expect(described_class.plan_open?(state: st)).to eq true
      unfinished = described_class.unfinished_tasks(state: st).map { |t| t[:item] }
      expect(unfinished.join(' ')).to match(/Implement|Verify/i)
    end

    it 'about_to plans a question-shaped request with no request type' do
      req = 'what flags does nmap use for a ping scan?'
      st = described_class.fresh(request: req)
      described_class.about_to(tools: [{ name: 'shell', args: { 'command' => 'man nmap' } }], state: st)
      expect(st).not_to have_key(:request_kind)
    end
  end

  describe 'original request visibility and PLAN: wrapper resistance' do
    let(:original) do
      'Fix TaskSummarizer so that it has visibility of the original request made by the user so tasks are relevant to the original request.'
    end
    let(:wrapped) do
      <<~REQ
        REQUEST:
        GOAL: #{original}

        PLAN:
        1. shell command="rg -n --glob '!{vendor,tmp,pkg,.git,coverage}/**' -e 'TaskSummarizer|task_summarizer' /opt/pwn/lib /opt/pwn/spec /opt/pwn/bin"
        2. shell command="sed -n '1,260p' /opt/pwn/lib/pwn/ai/agent/task_summarizer.rb"
        3. shell command="rg -n -e original_request /opt/pwn/lib/pwn/ai"
      REQ
    end

    it 'canonical_request strips GOAL/PLAN wrappers down to the operator ask' do
      expect(described_class.canonical_request(request: wrapped)).to eq(original)
      expect(described_class.canonical_request(request: original)).to eq(original)
      collapsed = "GOAL: #{original} PLAN: 1. shell command=\"rg TaskSummarizer\" 2. shell command=\"sed -n 1,20p file\""
      expect(described_class.canonical_request(request: collapsed)).to eq(original)
    end

    it 'fresh pins original_request to the canonical ask, not the PLAN: scaffold' do
      st = described_class.fresh(request: wrapped)
      expect(st[:original_request]).to eq(original)
      expect(st[:request]).to eq(original)
      expect(st[:request]).not_to match(/shell command=/i)
    end

    it 'plan does not treat PLAN: tool-call enumerations as English tasks' do
      allow(described_class).to receive(:chat_for_plan).and_return(
        [
          'Locate the TaskSummarizer component and how it builds tasks',
          'Identify where the original user request is available in the call chain',
          'Update TaskSummarizer so it receives and uses the original user request',
          'Verify generated tasks stay relevant to that original request'
        ].to_json
      )
      st = described_class.fresh(request: wrapped)
      tasks = described_class.plan(request: wrapped, state: st)
      expect(st[:plan_source]).not_to eq(:enumerated)
      expect(tasks.join(' ')).not_to match(/shell command=/i)
      expect(tasks.join(' ').downcase).to match(/original/)
      expect(st[:original_request]).to eq(original)
    end

    it 'plan_context and compact focus restate the original request' do
      st = described_class.fresh(request: wrapped)
      st[:plan] = [
        'Locate the TaskSummarizer component',
        'Identify request visibility in the call chain',
        'Update TaskSummarizer to use the original request'
      ]
      st[:plan_idx] = 0
      st[:plan_emitted] = true

      ctx = described_class.plan_context(state: st)
      expect(ctx).to include("Original request (immutable): #{original}")
      expect(ctx).not_to include('shell command=')

      first = described_class.active_task_prompt(state: st, force: true)
      expect(first).to include("Original request (immutable): #{original}")

      st[:plan_idx] = 1
      nxt = described_class.active_task_prompt(state: st)
      expect(nxt).to include("Original request (immutable): #{original}")
    end

    it 'still honors genuine English numbered steps from the user' do
      req = 'Do three things. 1. locate the file 2. patch the truncation 3. add plan on submit'
      tasks = described_class.plan(request: req)
      expect(tasks.length).to be >= 3
      expect(tasks[0].downcase).to include('locate')
      expect(tasks[1].downcase).to match(/patch|truncat/)
    end
  end
end
# rubocop:enable Metrics/BlockLength
