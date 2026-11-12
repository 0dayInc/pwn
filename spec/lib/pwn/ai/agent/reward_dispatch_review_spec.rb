# frozen_string_literal: true

require 'spec_helper'
require 'pwn/ai/agent/tools/ruby_eval'
require 'pwn/ai/agent/tools/shell'

RSpec.describe 'AI learning dispatch result review' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    @agent_cfg[:reward_llm] = false
    PWN::Env[:ai][:sandbox] = 'off'
    @saved_runtime = Thread.current[:pwn_request_runtime]
    Thread.current[:pwn_request_runtime] = nil
    stub_const('PWN::AI::Agent::Engagement::ROOT', File.join(@tmp, 'engagements'))
    stub_const('PWN::AI::Agent::Engagement::ACTIVE_FILE', File.join(@tmp, 'engagements', 'active'))
  end

  after do
    Thread.current[:pwn_request_runtime] = @saved_runtime
  end

  def dispatch(name, args)
    PWN::AI::Agent::Dispatch.call(tool_call: { id: 'outcome-fixture', function: { name: name, arguments: JSON.generate(args) } })
  end

  ["{success: false, error: 'File.write failed in the fixture'}", "{'ok' => false}"].each do |code|
    it "separates completed evaluation from application failure for #{code}" do
      raw = dispatch('pwn_eval', code: code, timeout: 3)
      result = JSON.parse(raw)
      expect(result.dig('result', 'value')).to include('false')
      expect(PWN::AI::Agent::Reward.semantic_ok(name: 'pwn_eval', raw: raw)).to include(semantic_ok: false)
      expect(result.dig('result', 'execution_success')).to be(true)
      expect(result.dig('result', 'application_status')).to eq('failed')
      state = PWN::AI::Agent::TaskSummarizer.fresh(request: 'Write the required report')
      state[:plan] = ['Write the required report', 'Present the report']
      PWN::AI::Agent::TaskSummarizer.record!(state: state, name: 'pwn_eval', args: { code: code }, result: raw)
      expect(state[:plan_idx]).to eq(0)
      expect(PWN::AI::Agent::Reward.prm(request: state[:request], trace: ["pwn_eval → #{raw}"]).first[:reward]).to eq(-1)
    end
  end

  it 'does not let a provider override an observed application failure with positive credit' do
    @agent_cfg[:reward_llm] = true
    allow(PWN::AI::Ollama).to receive(:chat).and_return('1')
    raw = dispatch('pwn_eval', code: '{success: false}', timeout: 3)
    expect(PWN::AI::Agent::Reward.prm(request: 'original request', trace: ["pwn_eval → #{raw}"]).first[:reward]).to be <= 0
  end

  it 'keeps a Loop-capped successful observation unknown rather than inventing a negative reward' do
    PWN::Env[:ai][:active] = :openai
    raw = dispatch('pwn_eval', code: "'a' * 1500", timeout: 3)
    expect(PWN::AI::Agent::Reward.semantic_ok(name: 'pwn_eval', raw: raw)[:semantic_ok]).to be(true)
    conditioned = PWN::AI::Agent::Result.condition(content: raw, entry: PWN::AI::Agent::Registry.lookup(name: 'pwn_eval'))
    cap = PWN::AI::Agent::Loop.send(:session_tool_budget, name: 'pwn_eval', result: conditioned)
    sid = PWN::Sessions.create(title: 'capped result fixture')[:id]
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'original request')
    PWN::Sessions.append(session_id: sid, role: 'tool', content: "pwn_eval → #{conditioned[0, cap]}")
    rows = PWN::AI::Agent::Reward.prm(request: 'original request', session_id: sid)
    expect(rows.first[:reward]).to be_nil
    expect(PWN::Sessions.load(session_id: sid).last[:step_reward]).to be_nil
    expect(PWN::AI::Agent::Metrics.prm_n(name: 'pwn_eval')).to eq(0)
  end

  it 'keeps malformed and untyped status evidence unknown even if a judge returns a score' do
    @agent_cfg[:reward_llm] = true
    allow(PWN::AI::Ollama).to receive(:chat).and_return('1')
    ['shell → {"success":true', 'shell → timeout success:false', 'shell → {"result":{"stdout":"success"}}'].each do |trace|
      expect(PWN::AI::Agent::Reward.semantic_ok(name: 'shell', raw: trace)).to include(semantic_ok: nil, shape: :unknown)
      expect(PWN::AI::Agent::Reward.prm(request: 'original request', trace: [trace]).first[:reward]).to be_nil
    end
  end

  it 'does not persist unknown capped observations as Loop mistakes or failure metrics' do
    raw = dispatch('pwn_eval', code: "'a' * 1500", timeout: 3)
    verdict = PWN::AI::Agent::Loop.send(:record_metrics, name: 'pwn_eval', raw: raw[0, 64], args: { code: 'inert fixture' })
    expect(verdict).to include(ok: nil, mistake: nil)
    expect(PWN::AI::Agent::Metrics.summary).to be_empty
    expect(File).not_to exist(PWN::AI::Agent::Mistakes::MISTAKES_FILE)
  end

  it 'classifies an actual informational grep miss without a false timeout fingerprint' do
    args = { command: 'grep absent /dev/null', timeout: 3 }
    raw = dispatch('shell', args)
    expect(JSON.parse(raw).dig('result', 'exit')).to eq(1)
    expect(PWN::AI::Agent::Reward.semantic_ok(name: 'shell', raw: raw, args: args)).to include(ok: false, semantic_ok: true, benign: true, shape: nil)
  end

  it 'preserves informational shell classification in the retained PRM trace without argv' do
    raw = dispatch('shell', command: 'grep absent /dev/null', timeout: 3)
    sid = PWN::Sessions.create(title: 'informational observation')[:id]
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'Find a matching record')
    PWN::Sessions.append(session_id: sid, role: 'tool', content: "shell → #{raw}")
    steps = PWN::AI::Agent::Reward.prm(request: 'Find a matching record', session_id: sid)
    expect(steps.first[:reward]).to eq(0)
    expect(PWN::Sessions.load(session_id: sid).last[:step_reward]).to eq(0)
  end

  it 'keeps real failures distinct from timeout configuration and informational exits' do
    ['false', 'grep absent /dev/null | false', 'grep absent /nonexistent-fixture'].each do |command|
      raw = dispatch('shell', command: command, timeout: 3)
      verdict = PWN::AI::Agent::Reward.semantic_ok(name: 'shell', raw: raw, args: { command: command })
      expect(verdict).to include(semantic_ok: false, benign: false)
      expect(verdict[:shape]).not_to eq(:timeout)
    end
  end

  it 'does not credit failed write text to a later real successful no-op' do
    state = PWN::AI::Agent::TaskSummarizer.fresh(request: 'Write the required report')
    state[:plan] = ['Write the required report', 'Present the report']
    ["{success: false, error: 'File.write could not create report'}", '1 + 1'].each do |code|
      raw = dispatch('pwn_eval', code: code, timeout: 3)
      PWN::AI::Agent::TaskSummarizer.record!(state: state, name: 'pwn_eval', args: { code: code }, result: raw)
      expect(state[:plan_idx]).to eq(0)
    end
    expect(state[:events].map { |row| row[:ok] }).to eq([false, true])
    expect(state[:request]).to eq('Write the required report')
  end

  it 'does not treat mutation words in successful no-op output as an observed write effect' do
    state = PWN::AI::Agent::TaskSummarizer.fresh(request: 'Write the required report')
    state[:plan] = ['Write the required report', 'Present the report']
    code = "'wrote the report'"
    raw = dispatch('pwn_eval', code: code, timeout: 3)
    PWN::AI::Agent::TaskSummarizer.record!(state: state, name: 'pwn_eval', args: { code: code }, result: raw)
    expect(state[:plan_idx]).to eq(0)
    expect(PWN::AI::Agent::TaskSummarizer.unfinished_tasks(state: state).map { |row| row[:idx] }).to include(0)
  end

  it 'preserves typed application failure across the sandbox boundary', :sandbox_outcome_boundary do
    PWN::Env[:ai][:sandbox] = 'permissive'
    expect(PWN::Plugins::AISandbox.mode).to eq(:permissive)
    raw = dispatch('pwn_eval', code: '{success: false}', timeout: 3)
    expect(JSON.parse(raw).dig('result', 'execution_success')).to be(true)
    expect(JSON.parse(raw).dig('result', 'application_status')).to eq('failed')
    expect(PWN::AI::Agent::Reward.semantic_ok(name: 'pwn_eval', raw: raw)[:semantic_ok]).to be(false)
  end

  it 'retains typed application and execution status even when a large result is paged' do
    raw = dispatch('pwn_eval', code: "{success: false, details: 'x' * 10000}", timeout: 3)
    parsed = JSON.parse(raw)
    expect(parsed).to include('success' => false, 'execution_success' => true, 'application_status' => 'failed')
    expect(parsed.dig('result', 'artifact')).not_to be_nil
  end

  it 'does not interpret stdout or inspected string values as application status' do
    raw = dispatch('pwn_eval', code: "puts '{\"success\":false}'; '{success: false}'", timeout: 3)
    result = JSON.parse(raw)
    expect(result.dig('result', 'execution_success')).to be(true)
    expect(result.dig('result', 'application_status')).to eq('unknown')
    expect(PWN::AI::Agent::Reward.semantic_ok(name: 'pwn_eval', raw: raw)).to include(semantic_ok: true)
  end
end
