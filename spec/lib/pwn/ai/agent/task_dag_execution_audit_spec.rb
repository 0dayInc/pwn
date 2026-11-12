# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::AI::Agent::TaskDAG, 'execution failure reporting' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
  end

  it 'preserves Dispatch failure when a shell command exits nonzero without an error field' do
    dag = described_class.plan(request: 'check command status', steps: [
                                 { id: 'probe', tool: 'shell', args: { command: 'exit 7', timeout: 5 } }
                               ])
    report = described_class.execute(dag: dag, root: @tmp, run_id: 'failed-exit')

    expect(report[:results].first[:result]).to include(exit: 7)
    expect(report[:results].first[:ok]).to be false
    expect(report[:ok]).to be false
  end

  it 'halts at failed prerequisites and retries them rather than skipping them on resume' do
    ready = File.join(@tmp, 'ready')
    output = File.join(@tmp, 'dependent.txt')
    dag = described_class.plan(request: 'wait for readiness then record it', steps: [
                                 { id: 'ready', tool: 'shell', args: { command: "test -f #{Shellwords.escape(ready)}", timeout: 5 } },
                                 { id: 'dependent', tool: 'shell', args: { command: "printf ready > #{Shellwords.escape(output)}", timeout: 5 }, dependencies: ['ready'] }
                               ])
    report = described_class.execute(dag: dag, root: @tmp, run_id: 'retry-failed')

    expect(report[:ok]).to be false
    expect(File.exist?(output)).to be false
    expect(report[:results].map { |row| row[:id] }).to eq(['ready'])
    checkpoints = File.join(@tmp, 'retry-failed', 'checkpoints.jsonl')
    expect(JSON.parse(File.read(checkpoints))).to include('id' => 'ready', 'status' => 'failed')

    File.write(ready, 'ready')
    resumed = described_class.resume(root: @tmp, run_id: 'retry-failed')
    expect(resumed[:ok]).to be true
    expect(resumed[:results].map { |row| row[:id] }).to eq(%w[ready dependent])
    expect(File.read(output)).to eq('ready')
    expect(File.readlines(checkpoints).map { |line| JSON.parse(line)['status'] }).to eq(%w[failed completed completed])
  end
end
