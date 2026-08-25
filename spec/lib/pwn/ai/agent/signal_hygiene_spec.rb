# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'tmpdir'

describe 'P0 signal hygiene (handler + inbox + policy-cold + calibrate)' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/shell.rb'
    load '/opt/pwn/lib/pwn/ai/agent/tools/ruby_eval.rb'
  end

  it 'rejects placeholder / ellipsis shell payloads before Open3' do
    handler = PWN::AI::Agent::Registry.lookup(name: 'shell').handler
    %w[... {…} {...}].each do |junk|
      r = handler.call(command: junk)
      expect(r[:error]).to eq('invalid_payload')
      expect(r[:hint].to_s).to match(/command is required/i)
    end
  end

  it 'maps wrong-key shell value= onto command' do
    handler = PWN::AI::Agent::Registry.lookup(name: 'shell').handler
    r = handler.call(value: 'echo schema_alias_ok')
    expect(r[:error]).to be_nil
    expect(r[:exit]).to eq(0)
    expect(r[:stdout].to_s).to include('schema_alias_ok')
    expect(r[:shell].to_s).to include('sh')
  end

  it 'rejects bashisms unless shell_bash is on' do
    handler = PWN::AI::Agent::Registry.lookup(name: 'shell').handler
    r = handler.call(command: 'echo ${PIPESTATUS[0]}')
    expect(r[:error]).to eq('invalid_payload')
    expect(r[:hint].to_s).to match(/bash-only/i)
  end

  it 'rejects $RANDOM under /bin/sh so the model rewrites instead of getting USER=' do
    expect(PWN::AI::Agent::ToolGuard.bashism?(text: 'U="p4tester$RANDOM"; echo $U')).to eq(true)
    handler = PWN::AI::Agent::Registry.lookup(name: 'shell').handler
    r = handler.call(command: 'U="p4tester$RANDOM"; echo $U')
    expect(r[:error]).to eq('invalid_payload')
    expect(r[:hint].to_s).to match(/RANDOM|bash-only|POSIX/i)
  end

  it 'does not refuse pwn_eval host-discovery as unauthorized' do
    src = File.read('/opt/pwn/lib/pwn/ai/agent/tools/ruby_eval.rb')
    expect(src).not_to match(/recon_blocked/)
    handler = PWN::AI::Agent::Registry.lookup(name: 'pwn_eval').handler
    r = handler.call(code: '1 + 1')
    expect(r[:error]).not_to eq('unauthorized_recon_blocked')
  end

  it 'Dispatch aliases value= onto command; handler reports schema errors' do
    out = PWN::AI::Agent::Dispatch.call(
      tool_call: {
        id: 't1', type: 'function',
        function: { name: 'shell', arguments: JSON.generate(value: 'echo dispatch_alias_ok') }
      }
    )
    parsed = JSON.parse(out, symbolize_names: true)
    expect(parsed[:success]).to eq(true)
    expect(parsed.dig(:result, :stdout).to_s).to include('dispatch_alias_ok')

    missing = PWN::AI::Agent::Dispatch.call(
      tool_call: {
        id: 't2', type: 'function',
        function: { name: 'shell', arguments: '{}' }
      }
    )
    parsed2 = JSON.parse(missing, symbolize_names: true)
    expect(parsed2[:success]).to eq(true)
    expect(parsed2.dig(:result, :error)).to eq('invalid_payload')
    expect(parsed2.dig(:result, :hint).to_s).to match(/Expected keys: command/i)
  end

  it 'promotes parked scars to an operator inbox and skips practice' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Mistakes::MISTAKES_FILE', File.join(tmp, 'mistakes.json'))
    PWN::AI::Agent::Mistakes.reset if PWN::AI::Agent::Mistakes.respond_to?(:reset)
    m = PWN::AI::Agent::Mistakes.record(tool: 'shell', error: 'enoent placeholder unique inbox')
    PWN::AI::Agent::Mistakes.park(signature: m[:signature], reason: 'needs_code_change')
    inbox = PWN::AI::Agent::Mistakes.operator_inbox
    expect(inbox[:count]).to be >= 1
    expect(inbox[:items].map { |i| i[:signature] }).to include(m[:signature])
    prac = PWN::AI::Agent::Mistakes.top(unresolved_only: true, practiceable_only: true)
    expect(prac.map { |r| r[:signature] }).not_to include(m[:signature])
  end

  it 'omits a greedy suggestion while the policy table is cold' do
    tmp = Dir.mktmpdir
    stub_const('PWN::AI::Agent::Policy::POLICY_FILE', File.join(tmp, 'policy.json'))
    stub_const('PWN::AI::Agent::Policy::TRAJECTORY_FILE', File.join(tmp, 'traj.jsonl'))
    PWN::AI::Agent::Policy.reset
    allow(PWN::AI::Agent::Policy).to receive(:enabled?).and_return(true)
    ctx = PWN::AI::Agent::Policy.to_context
    expect(ctx).to include('policy cold')
    expect(ctx).not_to match(/suggest=shell/)
  ensure
    PWN::AI::Agent::Policy.reset
  end

  it 'aggregates Metrics.calibration across engines' do
    stub_const('PWN::AI::Agent::Metrics::METRICS_FILE', File.join(Dir.mktmpdir, 'm.json'))
    PWN::AI::Agent::Metrics.reset
    PWN::AI::Agent::Curriculum.calibrate(predicted: 0.9, actual: 0.3, engine: :grok)
    PWN::AI::Agent::Curriculum.calibrate(predicted: 0.8, actual: 1.0, engine: :ollama)
    all = PWN::AI::Agent::Metrics.calibration
    expect(all[:n]).to eq(2)
    one = PWN::AI::Agent::Metrics.calibration(engine: :ollama)
    expect(one[:n]).to eq(1)
  end

  it 'treats review/opinion asks as goals with no request type' do
    allow(PWN::Env).to receive(:dig).and_call_original
    allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_llm).and_return(false)
    expect(PWN::AI::Agent::TaskSummarizer).not_to respond_to(:request_kind)
    expect(PWN::AI::Agent::TaskSummarizer.needs_task_breakdown?(request: 'suggest areas for improvement')).to eq(true)
    expect(PWN::AI::Agent::TaskSummarizer.needs_task_breakdown?(request: 'fix all the issues you just described')).to eq(true)
  end
end
