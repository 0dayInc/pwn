# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'open3'
require 'rbconfig'
require 'digest'
require 'timeout'

# All snapshot reads/writes and subprocess HOME directories are disposable.
describe 'PWN::AI::Agent::PolicyEvaluation' do
  around do |example|
    Dir.mktmpdir('pwn-evaluation-spec-', '/tmp') do |root|
      @root = root
      @baseline = File.join(root, 'baseline.json')
      @candidate = File.join(root, 'candidate.json')
      @blank = { q: {}, h: {}, visits: {}, returns: [], n_updates: 0, td_abs_sum: 0.0, updated_at: nil }
      File.write(@baseline, JSON.generate(@blank))
      File.write(@candidate, JSON.generate(@blank))
      example.run
    end
  end

  it 'cleans up the evaluation process group even after its leader exits' do
    expect(Process).to receive(:kill).with('KILL', be < 0).and_call_original
    PWN::AI::Agent::PolicyEvaluation.evaluate(baseline: @baseline, candidate: @candidate, seed: 0)
  end

  it 'runs frozen snapshots in cleared subprocess environments with independently checked artifacts' do
    expect(PWN::AI::Agent.const_defined?(:PolicyEvaluation)).to be(true)
    evaluator = PWN::AI::Agent::PolicyEvaluation
    before = File.binread(@candidate)
    report = evaluator.evaluate(baseline: @baseline, candidate: @candidate, seed: 0)
    expect(report[:protocol]).to eq('pwn-policy-heldout-v2')
    expect(report[:snapshot_sha256][:candidate]).to eq(Digest::SHA256.hexdigest(before))
    expect(report[:arms].keys).to eq(%i[off baseline candidate])
    report[:arms].each_value do |arm|
      expect(arm[:policy_frozen]).to be(true)
      expect(arm[:evaluation][:tasks]).to eq(8)
      expect(arm[:negative_controls]).to all(include(completed: false, false_success: true))
      expect(arm[:positive_controls]).to all(include(completed: true))
      expect(arm[:evaluation][:rows]).to all(have_key(:artifact_content))
      scores = arm[:evaluation][:rows].map { |row| row.fetch(:artifact_check_score) }
      expect(scores).to eq(arm[:evaluation][:rows].map { |row| row[:completed] ? 1.0 : 0.0 })
      expect(arm[:evaluation][:artifact_check_score]).to eq(scores.sum / scores.length)
      expect(arm).not_to have_key(:training)
    end
    expect(File.binread(@candidate)).to eq(before)
  end

  it 'varies held-out inputs and filesystem environments without changing the training split' do
    evaluator = PWN::AI::Agent::PolicyEvaluation
    first = evaluator.evaluate(baseline: @baseline, candidate: @candidate, seed: 0)
    second = evaluator.evaluate(baseline: @baseline, candidate: @candidate, seed: 1)
    a = first[:arms][:candidate]
    b = second[:arms][:candidate]
    expect(a[:fixtures][:heldout].map { |task| task[:input] } & b[:fixtures][:heldout].map { |task| task[:input] }).to be_empty
    expect(a[:fixtures][:training]).to eq(b[:fixtures][:training])
    expect(a[:environment]).not_to eq(b[:environment])
    expect(second[:isolation][:environment_keys]).to eq(%w[HOME LANG TMPDIR])
  end

  it 'exports learned snapshots and repeated independent reports only on explicit benchmark opt-in' do
    output, error, status = Open3.capture3(
      { 'HOME' => @root, 'LANG' => 'C.UTF-8' },
      RbConfig.ruby, File.expand_path('../../../../../scripts/benchmark_policy.rb', __dir__),
      '--heldout', '--snapshot-dir', File.join(@root, 'snapshots'), unsetenv_others: true
    )
    expect(status.success?).to be(true), error
    report = JSON.parse(output, symbolize_names: true)
    expect(report[:heldout].map { |row| row[:seed] }).to eq([0, 1])
    expect(File.file?(File.join(@root, 'snapshots', 'on.json'))).to be(true)
    report[:heldout].each do |row|
      expect(row[:arms][:candidate][:evaluation][:completed]).to eq(8)
      expect(row[:arms][:candidate][:evaluation][:completed]).to be > row[:arms][:baseline][:evaluation][:completed]
    end
    expect(report).not_to have_key(:promoted)
  end

  it 'requires opt-in and promotes a replay-verified candidate with a byte-exact rollback snapshot' do
    evaluator = PWN::AI::Agent::PolicyEvaluation
    expect(evaluator).to respond_to(:promote)
    live = File.join(@root, 'live.json')
    File.write(live, File.read(@baseline))
    expect(evaluator.promote(live_path: live)).to include(promoted: false, reason: 'disabled')
    output, error, status = Open3.capture3(
      { 'HOME' => @root, 'LANG' => 'C.UTF-8' }, RbConfig.ruby,
      File.expand_path('../../../../../scripts/benchmark_policy.rb', __dir__),
      '--heldout', '--snapshot-dir', File.join(@root, 'snapshots'), unsetenv_others: true
    )
    expect(status.success?).to be(true), error
    reports = JSON.parse(output, symbolize_names: true)[:heldout]
    baseline = File.join(@root, 'snapshots', 'off.json')
    candidate = File.join(@root, 'snapshots', 'on.json')
    File.write(live, File.read(baseline))
    File.unlink(live)
    File.symlink(baseline, live)
    rejected = evaluator.promote(enabled: true, quiescent: true, baseline: baseline, candidate: candidate, reports: reports, live_path: live)
    expect(rejected).to include(promoted: false, reason: 'snapshot path contains a symlink')
    File.unlink(live)
    File.write(live, File.read(baseline))
    result = evaluator.promote(enabled: true, quiescent: true, baseline: baseline, candidate: candidate, reports: reports, live_path: live)
    expect(result).to include(promoted: true, receipt_version: 1, change_kind: 'routing_policy')
    expect(result[:acceptance_sha256]).to match(/\A[0-9a-f]{64}\z/)
    [result.merge(promoted: false), result.merge(receipt_version: 2), result.except(:receipt_version), result.merge(change_kind: 'skill'), result.merge(acceptance_sha256: 'invalid')].each do |invalid|
      expect(evaluator.rollback(enabled: true, quiescent: true, live_path: live, receipt: invalid)).to include(rolled_back: false, reason: /receipt/)
      expect(File.binread(live)).to eq(File.binread(candidate))
    end
    expect(File.binread(live)).to eq(File.binread(candidate))
    expect(File.binread(result[:rollback_path])).to eq(File.binread(baseline))
    expect(result[:replayed_seeds]).to eq([0, 1])
    expect(evaluator).to respond_to(:rollback)
    expect(evaluator.rollback(receipt: result)).to include(rolled_back: false, reason: 'disabled')
    # A changed backup or intervening live update must not be silently replaced.
    File.write(result[:rollback_path], '{}')
    expect(evaluator.rollback(enabled: true, quiescent: true, live_path: live, receipt: result)).to include(rolled_back: false)
    File.write(result[:rollback_path], File.read(baseline))
    File.write(live, JSON.generate(@blank.merge(n_updates: 9)))
    expect(evaluator.rollback(enabled: true, quiescent: true, live_path: live, receipt: result)).to include(rolled_back: false)
    File.write(live, File.read(candidate))
    expect(evaluator.rollback(enabled: true, quiescent: true, live_path: live, receipt: result)).to include(rolled_back: true)
    expect(File.binread(live)).to eq(File.binread(baseline))
  end

  it 'rejects malformed or oversized snapshots, symlink paths, and out-of-protocol suite indices before execution' do
    evaluator = PWN::AI::Agent::PolicyEvaluation
    ['{}', JSON.generate(@blank.merge(q: { state: { action: 'not-a-number' } })), ' ' * 4_194_305].each do |bytes|
      File.write(@candidate, bytes)
      expect { evaluator.evaluate(baseline: @baseline, candidate: @candidate, seed: 0) }.to raise_error(ArgumentError, /snapshot/)
    end
    File.unlink(@candidate)
    File.symlink(@baseline, @candidate)
    expect { evaluator.evaluate(baseline: @baseline, candidate: @candidate, seed: 0) }.to raise_error(ArgumentError, /symlink/)
    File.unlink(@candidate)
    File.write(@candidate, JSON.generate(@blank))
    [-1, 8, '1', 0.5].each do |seed|
      expect { evaluator.evaluate(baseline: @baseline, candidate: @candidate, seed: seed) }.to raise_error(ArgumentError, /seed/)
    end
  end

  it 'terminates and reaps a stalled evaluator rather than leaving an unbounded child' do
    evaluator = PWN::AI::Agent::PolicyEvaluation
    worker = File.join(@root, 'stalled.rb')
    pidfile = File.join(@root, 'worker.pid')
    File.write(worker, "File.write(#{pidfile.inspect}, Process.pid.to_s); sleep 3")
    stub_const('PWN::AI::Agent::PolicyEvaluation::RUNNER', worker)
    stub_const('PWN::AI::Agent::PolicyEvaluation::WORKER_TIMEOUT_SECONDS', 1)
    expect { evaluator.evaluate(baseline: @baseline, candidate: @candidate, seed: 0) }.to raise_error(Timeout::Error)
    pid = File.read(pidfile).to_i
    expect { Process.kill(0, pid) }.to raise_error(Errno::ESRCH)
  end

  it 'rejects training-only gains, duplicate runs, forged provenance, scores, and artifact bodies without writes' do
    evaluator = PWN::AI::Agent::PolicyEvaluation
    File.write(@candidate, JSON.generate(@blank.merge(returns: [1.0] * 200, n_updates: 999)))
    reports = [0, 1].map { |seed| evaluator.evaluate(baseline: @baseline, candidate: @candidate, seed: seed) }
    live = File.join(@root, 'live.json')
    File.write(live, File.read(@baseline))
    args = { enabled: true, quiescent: true, baseline: @baseline, candidate: @candidate, live_path: live }
    expect(evaluator.promote(args.merge(reports: reports))).to include(promoted: false, reason: /training-only/)
    expect(evaluator.promote(args.merge(reports: [reports.first, reports.first]))).to include(promoted: false, reason: /distinct/)
    [
      ->(report) { report[:source_sha256][:policy] = '0' * 64 },
      ->(report) { report[:snapshot_sha256][:candidate] = '1' * 64 },
      ->(report) { report[:arms][:candidate][:evaluation][:completed] = 8 },
      ->(report) { report[:arms][:candidate][:evaluation][:rows].first[:artifact_content] = '["forged PASS"]' },
      ->(report) { report[:passed] = true }
    ].each do |tamper|
      changed = Marshal.load(Marshal.dump(reports))
      tamper.call(changed.first)
      expect(evaluator.promote(args.merge(reports: changed))).to include(promoted: false, reason: %r{provenance/artifact})
    end
    expect(File.binread(live)).to eq(File.binread(@baseline))
    expect(Dir.glob("#{live}.rollback-*")).to be_empty
  end

  it 'rejects a per-task regression even when aggregate completion appears better' do
    evaluator = PWN::AI::Agent::PolicyEvaluation
    report = evaluator.evaluate(baseline: @baseline, candidate: @candidate, seed: 0)
    # Unit-only fault injection into real runner output, not evaluation evidence.
    candidate = report[:arms][:candidate][:evaluation]
    candidate[:completed] += 1
    row = candidate[:rows].find { |attempt| attempt[:completed] }
    row[:completed] = false
    expect { evaluator.send(:gate, report: report) }.to raise_error(ArgumentError, /task regression/)
  end

  it 'enforces artifact scores, completion, false-success, repeated-mistake, call, and measured-time gates' do
    evaluator = PWN::AI::Agent::PolicyEvaluation
    original = evaluator.evaluate(baseline: @baseline, candidate: @candidate, seed: 0)
    %i[artifact_check_score completed false_successes false_success_rate repeated_mistakes tool_calls elapsed_seconds].each do |metric|
      report = Marshal.load(Marshal.dump(original))
      candidate = report[:arms][:candidate][:evaluation]
      candidate[:completed] += 1 # Unit-only fault injection: otherwise no gain.
      direction = %i[artifact_check_score completed].include?(metric) ? -1 : 1
      candidate[metric] = report[:arms][:baseline][:evaluation][metric] + direction
      expected = metric == :completed ? 'completion' : metric.to_s
      expect { evaluator.send(:gate, report: report) }.to raise_error(ArgumentError, /#{expected} regression/)
    end
  end

  it 'requires repeated reports to cover both filesystem environments' do
    evaluator = PWN::AI::Agent::PolicyEvaluation
    reports = [0, 2].map { |seed| evaluator.evaluate(baseline: @baseline, candidate: @candidate, seed: seed) }
    result = evaluator.promote(enabled: true, quiescent: true, baseline: @baseline, candidate: @candidate, live_path: @baseline, reports: reports)
    expect(result).to include(promoted: false, reason: /environments/)
  end

  it 'rejects named pipes before opening snapshot input' do
    File.unlink(@candidate)
    File.mkfifo(@candidate)
    expect do
      Timeout.timeout(0.5) { PWN::AI::Agent::PolicyEvaluation.evaluate(baseline: @baseline, candidate: @candidate) }
    end.to raise_error(ArgumentError, /regular file/)
  end

  it 'exercises the snapshot worker as part of the standalone script self-check' do
    output, error, status = Open3.capture3(
      { 'HOME' => @root, 'LANG' => 'C.UTF-8' }, RbConfig.ruby,
      File.expand_path('../../../../../scripts/benchmark_policy.rb', __dir__),
      '--self-check', unsetenv_others: true
    )
    expect(status.success?).to be(true), error
    expect(output).to include('Snapshot self-checks passed', 'Self-checks passed')
  end
end
