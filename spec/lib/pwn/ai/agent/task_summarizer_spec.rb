# frozen_string_literal: true

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

  it 'format_plan method should exist' do
    expect(described_class).to respond_to :format_plan
  end

  describe 'executive high-level brief (one-to-many)' do
    let(:goal) { 'ship plain-English task briefs to executive management' }
    let(:state) { described_class.fresh(request: goal) }

    it 'summarizes a whole tool collection without dumping raw commands' do
      line = described_class.about_to(
        tools: [
          { name: 'shell', args: { 'command' => 'cat /opt/pwn/spec/lib/pwn/ai/agent/task_summarizer_spec.rb' } },
          { name: 'pwn_eval', args: { 'code' => '1+1' } }
        ],
        state: state
      )
      expect(line).to be_a(String)
      expect(line).to match(/Next:/i)
      expect(line).to include('shell')
      expect(line).to include('pwn_eval')
      # Intent makes the batch distinctive (read vs edit vs search)
      expect(line).to match(/read|eval-ruby/i)
      # Plan item linkage (or full goal when no plan) — no raw dumps
      expect(line).to match(%r{task \d+/|toward:}i)
      # No low-level command / path dump in the task brief
      expect(line).not_to include('cat /opt/pwn')
      expect(line).not_to include('task_summarizer_spec')
      expect(line).not_to include('1+1')
      expect(line).not_to match(/about to run shell:/i)
    end

    it 'keeps single-tool legacy about_to(name, args) as a high-level brief' do
      line = described_class.about_to(
        'shell',
        { 'command' => 'rg TaskSummarizer /opt/pwn' },
        state: state
      )
      expect(line).to match(/Next:/i)
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

    it 'record! stays silent by default (no result-bearing task spam)' do
      allow(PWN::Env).to receive(:dig).and_call_original
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_every).and_return(1)
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_interval_s).and_return(9_999)
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary).and_return(true)
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_verbose).and_return(false)

      described_class.about_to(tools: [{ name: 'shell' }], state: state)
      line = described_class.record!(state, 'shell', 'rake', '{success:true}')
      expect(line).to be_nil
      expect(state[:total]).to eq 1
    end

    it 'flush! closes with a plain-English done brief (still no raw result)' do
      allow(PWN::Env).to receive(:dig).and_call_original
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_verbose).and_return(false)

      described_class.about_to(tools: [{ name: 'shell' }, { name: 'shell' }], state: state)
      described_class.record!(state, 'shell', 'rake', '{success:true}')
      described_class.record!(state, 'shell', 'rake 2>&1', '{success:true}')
      fin = described_class.flush!(state)
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
      allow(PWN::Env).to receive(:dig).and_call_original
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_every).and_return(2)
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_interval_s).and_return(9_999)
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary).and_return(true)
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_verbose).and_return(true)

      expect(described_class.record!(state, 'shell', 'rake', '{success:true}')).to be_nil
      line = described_class.record!(state, 'memory_recall', 'task', '{success:true}')
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
      tasks = described_class.plan(request, state: state)
      expect(tasks).to be_a(Array)
      expect(tasks.length).to be >= 2
      expect(state[:plan]).to eq tasks
      joined = tasks.join(' | ').downcase
      expect(joined).to match(/display|entire|summary|truncat|full/)
      expect(joined).to match(/break|tangible|decompos|list/)
    end

    it 'format_plan / emit_plan! return the full multi-line summary (no 280-char cut)' do
      tasks = described_class.plan(request, state: state)
      text = described_class.emit_plan!(state)
      expect(text).to be_a(String)
      expect(text).to include('Goal:')
      expect(text).to include('Tangible tasks')
      expect(text).to include('1.')
      expect(text).to include('2.')
      expect(text).to include("\n")
      # Entire request goal retained — not hard-truncated to PREVIEW_LEN/280
      expect(text.length).to be > 120
      expect(text).not_to match(/…\z/)
      expect(state[:plan_emitted]).to eq true
      expect(state[:plan_text]).to eq text
      # Idempotent
      expect(described_class.emit_plan!(state)).to eq text
    end

    it 'about_to does not ellipsize long briefs and shows full plan text' do
      long_goal = "improve task summarizer end-to-end: #{'x' * 400}"
      st = described_class.fresh(request: long_goal)
      described_class.plan(long_goal, state: st)
      plan_text = described_class.emit_plan!(st)
      expect(plan_text.length).to be > 280
      expect(plan_text).to include(long_goal)
      expect(plan_text).not_to include('…')
      line = described_class.about_to(tools: [{ name: 'shell' }, { name: 'pwn_eval' }], state: st)
      expect(line).to be_a(String)
      expect(line).to match(/Next:/i)
      expect(line).not_to include('…')
      # Mid-flight brief stays distinctive; full goal lives on the plan line
      expect(line).to include('shell')
    end

    it 'enumerates explicit numbered steps from the request' do
      req = 'Do three things. 1. locate the file 2. patch the truncation 3. add plan on submit'
      tasks = described_class.plan(req)
      expect(tasks.length).to be >= 3
      expect(tasks[0].downcase).to include('locate')
      expect(tasks[1].downcase).to match(/patch|truncat/)
      expect(tasks[2].downcase).to match(/plan|submit/)
    end
  end
end
