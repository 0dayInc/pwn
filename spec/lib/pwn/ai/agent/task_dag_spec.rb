# frozen_string_literal: true

require 'spec_helper'
require 'yaml'
require 'json'
require 'tmpdir'
require 'fileutils'
require 'timeout'

describe PWN::AI::Agent::TaskDAG do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'emits a YAML DAG with steps, tool, args, side-effect tier, and dependencies' do
    expect(PWN::AI::Agent::Dispatch).not_to receive(:call)
    expect(PWN::AI::Agent::Loop).not_to receive(:run)
    dag = described_class.plan(request: 'echo one then echo two')
    yaml = YAML.dump(JSON.parse(JSON.generate(dag)))
    parsed = YAML.safe_load(yaml)
    steps = parsed['steps'] || parsed[:steps]
    expect(steps.length).to be >= 2
    first = steps.first.transform_keys(&:to_s)
    expect(first).to include('id', 'tool', 'args', 'side_effect', 'dependencies')
    expect(%w[read_only active_scan exploit destructive]).to include(first['side_effect'])
  end

  it 'skips completed steps after a killed executor is resumed' do
    Dir.mktmpdir('pwn-dag-') do |dir|
      log = File.join(dir, 'log.txt')
      dag = {
        'version' => 1,
        'request' => 'two-step',
        'steps' => [
          { 'id' => 's1', 'tool' => 'shell', 'args' => { 'command' => "printf first >> #{log}" }, 'side_effect' => 'read_only', 'dependencies' => [] },
          { 'id' => 's2', 'tool' => 'shell', 'args' => { 'command' => "printf second >> #{log}" }, 'side_effect' => 'read_only', 'dependencies' => ['s1'] }
        ]
      }
      PWN::AI::Agent::Registry.discover(force: true)
      load '/opt/pwn/lib/pwn/ai/agent/tools/shell.rb'
      run_id = 'kill-resume'
      pid = Process.fork do
        described_class.execute(dag: dag, run_id: run_id, root: dir, halt_after: 's1')
        exit!
      end
      begin
        Timeout.timeout(10) do
          Process.wait(pid)
        end
      rescue Timeout::Error
        Process.kill('KILL', pid)
        Process.wait(pid)
      end
      expect(File.read(log)).to eq('first')
      described_class.execute(run_id: run_id, root: dir)
      expect(File.read(log)).to eq('firstsecond')
    end
  end
end
