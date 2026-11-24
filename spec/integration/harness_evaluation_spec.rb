# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require_relative '../support/harness/evaluate'
require_relative '../support/harness/experiments'

RSpec.describe 'offline harness evaluation' do
  it 'refuses unknown or unequal comparison identities before launching anything' do
    pinned = { 'provider' => 'fixture', 'model' => 'fixture-v1', 'revision' => 'immutable-1',
               'endpoint' => 'offline', 'reasoning' => 'none', 'temperature' => 0,
               'max_iterations' => 6, 'max_tokens' => 1000, 'wall_seconds' => 30,
               'tool_capabilities' => ['local_shell'], 'network' => false }
    expect(HarnessEvaluation.validate_parity!(pinned, pinned.dup)).to eq(:validated)
    %w[provider model revision].each do |key|
      [nil, '', 'unknown'].each do |value|
        bad = pinned.merge(key => value)
        expect { HarnessEvaluation.validate_parity!(bad, bad) }.to raise_error(ArgumentError)
      end
    end
    expect { HarnessEvaluation.validate_parity!(pinned, pinned.merge('provider' => 'different')) }.to raise_error(ArgumentError)
  end

  it 'counts claims without checks, nonzero exits, and capped claims as false completion' do
    Dir.mktmpdir do |root|
      corpus = HarnessExperiments.locked_json(File.join(HarnessEvaluation::ROOT, 'spec/fixtures/harness/completion_regressions.json'))
      expect(corpus.fetch('split')).to eq('regression')
      File.write(File.join(root, 'result.txt'), 'correct')
      corpus.fetch('cases').each do |failure|
        task = { 'checks' => failure.fetch('checks'), 'success_marker' => 'DONE' }
        result = failure.fetch('result').transform_keys(&:to_sym)
        expect(HarnessEvaluation.grade(task, root, result)).to include(outcome: failure.fetch('outcome'), false_success: true), failure.fetch('id')
      end
    end
  end

  it 'grades independent bytes and counts observed repeated identities, not tool attempts' do
    Dir.mktmpdir do |root|
      File.write(File.join(root, 'result.txt'), 'wrong')
      File.write(File.join(root, 'effects.log'), "first\nsecond\nfirst\n")
      task = { 'checks' => [{ 'path' => 'result.txt', 'bytes' => 'correct' }], 'success_marker' => 'DONE' }
      result = { stdout: 'DONE', exit_status: 0, resource_cap: false }
      expect(HarnessEvaluation.grade(task, root, result)).to include(outcome: 'FAIL', false_success: true, repeated_effects: 1)
      expect(HarnessEvaluation.grade(task, root, result.merge(resource_cap: true))).to include(outcome: 'INCOMPLETE')
      File.write(File.join(root, 'effects.log'), "first\nsecond\n")
      expect(HarnessEvaluation.grade(task, root, result)[:repeated_effects]).to eq(0)
      File.write(File.join(root, 'events.jsonl.tools'), "#{JSON.generate(result: { success: false, result: { error: 'timeout' } })}\n")
      expect(HarnessEvaluation.grade(task, root, result.merge(stdout: 'blocked', exit_status: 1))).to include(outcome: 'INCOMPLETE', tool_timeouts: 1)
    end
  end

  it 'runs real CLI/Loop/tool effects and independently rejects a lying artifact claim', :aggregate_failures do
    Dir.mktmpdir('pwn-harness-spec-', '/tmp') do |root|
      report = JSON.parse(JSON.generate(HarnessEvaluation.run(output: root)))
      results = report.fetch('results').to_h { |row| [row.fetch('task'), row] }
      expect(results.keys.sort).to eq(%w[artifact-lie coding exact-file security-toy structured timeout-replay])
      %w[coding exact-file security-toy structured].each do |name|
        expect(results.fetch(name)).to include('outcome' => 'PASS', 'provider_calls' => 3, 'false_success' => false)
      end
      lie = results.fetch('artifact-lie')
      expect(lie).to include('outcome' => 'FAIL', 'false_success' => false, 'exit_status' => 1)
      timeout = results.fetch('timeout-replay')
      expect(timeout).to include('outcome' => 'INCOMPLETE', 'false_success' => false, 'exit_status' => 1, 'repeated_effects' => 0)
      expect(timeout.fetch('checks')).to all(include('passed' => true))
      expect(report.fetch('swarm_acceptance').fetch('results').map { |row| row.fetch('id') }).to eq(%w[correct lie stale missing tampered])
      expect(report.fetch('swarm_acceptance').fetch('results')).to all(include('outcome' => 'PASS'))
      expect(report.fetch('swarm_acceptance').fetch('results').drop(1)).to all(include('exit_status' => 1))
      expect(report.fetch('session_acceptance').fetch('results')).to all(include('outcome' => 'PASS', 'identity_preserved' => true))
      expect(report.fetch('model_comparison')['outcome']).to eq('NOT_RUN')
      results.each_value do |row|
        expect(row).to include('outcome' => row.fetch('expected_outcome'), 'false_success' => false, 'repeated_effects' => 0)
      end
      expect(report.fetch('runtime_fault_process')).to include('exit_status' => 0, 'resource_cap' => false)
      expect_frozen_experiments(report.fetch('experiments'))
      expect_cli_faults(report.fetch('cli_faults'))
      expect(report.fetch('runtime_faults').fetch('results').map { |row| row.fetch('outcome') }).to eq(%w[PASS PASS PASS PASS])
      expect(results.values).to all(include('tokens' => nil, 'cost' => nil))
    ensure
      Dir.glob(File.join(root, '**', '*'), File::FNM_DOTMATCH).each { |path| File.chmod(0o700, path) if File.directory?(path) }
    end
  end

  it 'arms a hard fault cap only after bounded executable startup readiness' do
    Dir.mktmpdir do |root|
      ready = File.join(root, 'ready')
      command = [RbConfig.ruby, '-e', "sleep 0.15; File.write(ARGV.fetch(0), 'ready'); sleep 60", ready]
      result = HarnessEvaluation.capture({ 'HOME' => root }, command, root, 0.05, ready_path: ready, startup_seconds: 2)
      expect(result).to include(resource_cap: true, ready_observed: true, exit_status: nil, signal: Signal.list.fetch('KILL'))
      expect(File.read(ready)).to eq('ready')
      expect(result[:latency_seconds]).to be < 3
    end
  end

  it 'caps an actual blocked subprocess and does not turn the cap into exit zero' do
    Dir.mktmpdir do |root|
      report = HarnessEvaluation.capture({ 'HOME' => root }, [RbConfig.ruby, '-e', 'sleep 60'], root, 0.05)
      expect(report).to include(resource_cap: true, exit_status: nil, signal: Signal.list.fetch('KILL'))
      expect(report[:latency_seconds]).to be < 3
    end
  end

  def expect_cli_faults(report)
    rows = report.fetch('results')
    expect(rows.map { |row| row.fetch('id') }).to eq(%w[compaction-steering provider-retry cancel-during-provider checkpoint-restart resource-cap-restart])
    expect(rows).to all(include('outcome' => 'PASS', 'tokens' => nil, 'cost' => nil))
    expect(report.fetch('model_quality')).to eq('NOT_RUN')
  end

  def expect_frozen_experiments(report)
    expect(report).to include('model_quality' => 'NOT_RUN', 'snapshot_unchanged' => true, 'input_manifests_unchanged' => true)
    rows = report.fetch('results')
    expect(rows.length).to eq(8)
    expect(rows).to all(include('outcome' => 'PASS', 'inputs_unchanged' => true, 'false_success' => false, 'repeated_effects' => 0, 'tokens' => nil, 'cost' => nil))
    arms = rows.group_by { |row| row.fetch('arm') }
    expect(arms.fetch('swarm-snapshot')).to all(include('nested_provider_calls' => 3))
    expect(arms.fetch('single-policy').map { |row| row.fetch('policy_episodes') }).to all(be > 0)
  end

  it 'requires explicit live approval before importing the reference agent or reading credentials' do
    source = File.read(File.join(HarnessEvaluation::ROOT, 'spec/support/harness/reference_adapter.py'))
    main = source.split('def main():', 2).last
    refusal = main.index('explicit --approve-live required')
    import_at = main.index('from run_agent import AIAgent')
    expect(refusal).not_to be_nil
    expect(import_at).not_to be_nil
    expect(refusal).to be < import_at
    expect(main).to include('if not args.approve_live and not args.inspect_source')
    expect(main).to include('no agent imported or credentials read')
  end

  it 'rejects manifest drift and cross-split input leakage before provider execution' do
    Dir.mktmpdir do |root|
      path = File.join(root, 'tasks.json')
      manifest = JSON.parse(File.read(File.join(HarnessEvaluation::ROOT, 'spec/fixtures/harness/experiment_tasks.json')))
      manifest['tasks'].last['input'] = manifest['tasks'].first['input']
      File.write(path, JSON.generate(manifest))
      File.write("#{path}.sha256", Digest::SHA256.file(path).hexdigest)
      expect { HarnessExperiments.run(output: File.join(root, 'runs'), manifest: path) }.to raise_error(/split leakage/)
      expect(File.exist?(File.join(root, 'runs'))).to be(false)
      File.write(path, '{}')
      expect { HarnessExperiments.locked_json(path) }.to raise_error(/hash mismatch/)
    end
  end

  it 'forwards same-model settings to the inspected reference API without importing or invoking it' do
    source = File.read(File.join(HarnessEvaluation::ROOT, 'spec/support/harness/reference_adapter.py'))
    parity = source.split('def parity(manifest):', 2).last.split('def constructor', 2).first
    constructor = source.split('def constructor(config, cwd, api_key):', 2).last.split('def main', 2).first
    %w[provider model revision].each do |key|
      expect(parity).to include(%("#{key}"))
    end
    expect(parity).to include('unknown')
    expect(constructor).to include('reasoning_config=config["reasoning"]')
    expect(constructor).to include('request_overrides={"temperature": config["temperature"]}')
    expect(constructor).to include('skip_memory=True')
    expect(constructor).to include('skip_background_review=True')
    expect(constructor).to include('max_tokens=config["max_tokens"]')
    expect(constructor).not_to include('import run_agent')
  end

  it 'pins separately authored fixture and adapter bytes' do
    %w[manifest adapters experiment_tasks experiment_gold live_comparison].each do |name|
      path = File.join(HarnessEvaluation::ROOT, "spec/fixtures/harness/#{name}.json")
      expect(Digest::SHA256.file(path).hexdigest).to eq(File.read("#{path}.sha256").strip)
    end
  end
end
