# frozen_string_literal: true

require_relative 'evaluate' unless defined?(HarnessEvaluation)

# Split-corpus CLI execution with immutable training input snapshots.
module HarnessExperiments
  ARMS = %w[single-cold single-snapshot single-policy swarm-snapshot].freeze

  def self.locked_json(path)
    bytes = File.binread(path)
    raise "manifest hash mismatch: #{path}" unless Digest::SHA256.hexdigest(bytes) == File.read("#{path}.sha256").strip

    JSON.parse(bytes)
  end

  def self.ledger(root)
    Dir.glob(File.join(root, '**', '*'), File::FNM_DOTMATCH).sort.each_with_object({}) do |path, hashes|
      raise "snapshot symlink refused: #{path}" if File.symlink?(path)
      next unless File.file?(path)

      hashes[path.delete_prefix("#{root}/")] = Digest::SHA256.file(path).hexdigest
    end
  end

  def self.tool(name, args, id)
    { role: 'assistant', tool_calls: [{ id: id, type: 'function', function: { name: name, arguments: JSON.generate(args) } }] }
  end

  def self.trial(task, arm, gold, snapshot, options)
    root = Dir.mktmpdir("#{task.fetch('id')}-#{arm}-", options.fetch(:output))
    home = File.join(root, 'home')
    FileUtils.mkdir_p(home)
    FileUtils.cp_r(File.join(snapshot, '.'), home) if snapshot && arm != 'single-cold'
    # The immutable source snapshot is never mounted as a writable live store.
    Dir.glob(File.join(home, '**', '*'), File::FNM_DOTMATCH).each { |path| File.chmod(File.directory?(path) ? 0o700 : 0o600, path) }
    File.write(File.join(root, 'input.txt'), task.fetch('input'))
    input_hash = Digest::SHA256.file(File.join(root, 'input.txt')).hexdigest
    policy_path = File.join(home, '.pwn/policy_traj.jsonl')
    prior_episodes = File.file?(policy_path) ? File.foreach(policy_path).count : 0
    final = { role: 'assistant', content: 'FIXTURE_COMPLETE', tool_calls: [] }
    steps = [tool('shell', { command: "#{task.fetch('command')}; printf 'result-write\\n' >> effects.log", timeout: 10 }, 'write'),
             tool('shell', { command: 'cat result.txt', timeout: 10 }, 'read'), final]
    if arm == 'swarm-snapshot'
      steps = [tool('agent_spawn', { name: 'fixture_worker', role: 'Execute the assigned local fixture task and verify actual bytes.',
                                     toolsets: ['shell'], engine: 'openai', model: 'offline-scripted-v1', max_iters: 6 }, 'spawn'),
               tool('agent_ask', { name: 'fixture_worker', request: task.fetch('prompt') }, 'ask')] + steps +
              [tool('shell', { command: 'cat result.txt', timeout: 10 }, 'parent-read'), final]
    end
    fixture = { responses: steps, seed: options.fetch(:seed, 0), toolsets: arm == 'swarm-snapshot' ? %w[shell swarm] : ['shell'],
                agent: { policy: arm == 'single-policy', max_iters: options.fetch(:max_iterations, 12) } }
    File.write(File.join(root, 'provider.json'), JSON.generate(fixture))
    source = options[:source_root] || HarnessEvaluation::ROOT
    env = { 'HOME' => home, 'PATH' => '/usr/bin:/bin', 'LANG' => 'C.UTF-8',
            'GEM_HOME' => options[:gem_home] || Gem.dir, 'GEM_PATH' => options[:gem_path] || Gem.path.join(File::PATH_SEPARATOR),
            'PWN_HARNESS_FIXTURE' => File.join(root, 'provider.json'), 'PWN_HARNESS_EVENTS' => File.join(root, 'events.jsonl'),
            'PWN_HARNESS_FINGERPRINT' => File.join(root, 'fingerprint.json'), 'PWN_HARNESS_OBSERVATIONS' => File.join(root, 'observations.json') }
    command = [RbConfig.ruby]
    command += ['-I', File.join(source, 'lib')] unless options[:executable]
    command += ['-r', File.join(source, 'scripts/harness/experiment_preload.rb'), options[:executable] || File.join(source, 'bin/pwn-ai'), '--ai', task.fetch('prompt')]
    result = HarnessEvaluation.capture(env, command, root, options.fetch(:wall_seconds, 35))
    grade = HarnessEvaluation.grade({ 'checks' => gold.fetch(task.fetch('id')), 'success_marker' => 'FIXTURE_COMPLETE' }, root, result)
    File.write(File.join(root, 'process.json'), JSON.pretty_generate(result.merge(command: command)))
    trace_path = File.join(root, 'events.jsonl')
    trace = File.file?(trace_path) ? File.readlines(trace_path, encoding: Encoding::UTF_8).map { |line| JSON.parse(line) } : []
    observations = File.file?(File.join(root, 'observations.json')) ? JSON.parse(File.read(File.join(root, 'observations.json'))) : {}
    grade.merge(task: task.fetch('id'), split: task.fetch('split'), arm: arm, prompt: task.fetch('prompt'), seed: options.fetch(:seed, 0),
                artifact_root: root, home: home, provider_calls: trace.length,
                nested_provider_calls: trace.count { |row| row['swarm_depth'].to_i.positive? },
                policy_episodes: (File.file?(policy_path) ? File.foreach(policy_path).count : 0) - prior_episodes,
                observations: observations, inputs_unchanged: Digest::SHA256.file(File.join(root, 'input.txt')).hexdigest == input_hash,
                input_sha256: input_hash, tokens: nil, cost: nil, latency_seconds: result[:latency_seconds],
                exit_status: result[:exit_status], resource_cap: result[:resource_cap])
  end

  def self.run(options)
    source = options[:source_root] || HarnessEvaluation::ROOT
    manifest_path = options[:manifest] || File.join(source, 'scripts/harness/experiment_tasks.json')
    gold_path = options[:gold] || File.join(source, 'scripts/harness/experiment_gold.json')
    manifest = locked_json(manifest_path)
    gold = locked_json(gold_path).fetch('checks')
    input_hashes = [manifest_path, gold_path].to_h { |path| [path, Digest::SHA256.file(path).hexdigest] }
    options = options.merge(seed: manifest.fetch('seed'))
    tasks = manifest.fetch('tasks')
    raise 'unsupported arm' unless manifest.fetch('arms').all? { |arm| ARMS.include?(arm) }
    raise 'duplicate task identity' unless tasks.map { |task| task.fetch('id') }.uniq.length == tasks.length
    raise 'split leakage: identical input or prompt' unless %w[input prompt].all? { |key| tasks.map { |task| task.fetch(key) }.uniq.length == tasks.length }
    raise 'train, validation and heldout required' unless tasks.map { |task| task.fetch('split') }.uniq.sort == %w[heldout train validation]
    raise 'gold task mismatch' unless gold.keys.sort == tasks.map { |task| task.fetch('id') }.sort

    output = options.fetch(:output)
    FileUtils.mkdir_p(output)
    snapshot = options[:frozen] ? File.join(options[:frozen], 'frozen-training-home') : File.join(output, 'frozen-training-home')
    raise 'output already contains a snapshot; choose a fresh output directory' if !options[:frozen] && File.exist?(snapshot)

    if options[:frozen]
      expected = JSON.parse(File.read(File.join(options[:frozen], 'snapshot-sha256.json')))
      raise 'frozen snapshot drift' unless ledger(snapshot) == expected && !expected.empty?
    end

    FileUtils.mkdir_p(snapshot) unless options[:frozen]
    train_tasks = options[:frozen] ? [] : tasks.select { |task| task.fetch('split') == 'train' }
    train = train_tasks.map do |task|
      row = trial(task, 'single-policy', gold, snapshot, options.merge(max_iterations: manifest.fetch('budget').fetch('max_iterations')))
      raise "training artifact failed: #{row.inspect}" unless row[:outcome] == 'PASS' && row[:inputs_unchanged]

      receipt = File.join(output, "#{task.fetch('id')}-receipt.json")
      File.write(receipt, JSON.generate(row))
      env = { 'HOME' => row[:home], 'PATH' => '/usr/bin:/bin', 'LANG' => 'C.UTF-8',
              'GEM_HOME' => options[:gem_home] || Gem.dir, 'GEM_PATH' => options[:gem_path] || Gem.path.join(File::PATH_SEPARATOR) }
      recorded = HarnessEvaluation.capture(env, [RbConfig.ruby, '-I', File.join(source, 'lib'), File.join(source, 'scripts/harness/record_training.rb'), receipt], output, 20)
      File.write(File.join(output, "#{task.fetch('id')}-learning.json"), JSON.pretty_generate(recorded))
      raise 'training learning receipt failed' unless recorded[:exit_status]&.zero?

      FileUtils.rm_rf(File.join(snapshot, '.pwn'))
      FileUtils.cp_r(File.join(row[:home], '.pwn'), snapshot)
      row
    end
    frozen = ledger(snapshot)
    File.write(File.join(output, 'snapshot-sha256.json'), JSON.pretty_generate(frozen))
    unless options[:frozen]
      Dir.glob(File.join(snapshot, '**', '*'), File::FNM_DOTMATCH).each { |path| File.chmod(File.directory?(path) ? 0o500 : 0o400, path) }
    end
    schedule = tasks.reject { |task| task.fetch('split') == 'train' }.flat_map { |task| manifest.fetch('arms').map { |arm| [task, arm] } }.shuffle(random: Random.new(manifest.fetch('seed')))
    trial_options = options.merge(wall_seconds: manifest.fetch('budget').fetch('wall_seconds'), max_iterations: manifest.fetch('budget').fetch('max_iterations'))
    results = schedule.map { |task, arm| trial(task, arm, gold, snapshot, trial_options) }
    report = { schema: 'pwn-frozen-experiments-v1', seed: manifest.fetch('seed'), model_quality: 'NOT_RUN',
               provenance: manifest.fetch('provenance'), manifest_sha256: input_hashes.fetch(manifest_path),
               gold_sha256: input_hashes.fetch(gold_path),
               input_manifests_unchanged: input_hashes.all? { |path, hash| Digest::SHA256.file(path).hexdigest == hash },
               schedule: schedule.map { |task, arm| { task: task.fetch('id'), arm: arm } },
               snapshot_sha256: Digest::SHA256.hexdigest(JSON.generate(frozen)), snapshot_unchanged: ledger(snapshot) == frozen,
               training: train, results: results,
               learning_scope: 'Cold vs cloned frozen whole training HOME stores; policy off/on. Real retrieval and policy paths, private per-trial writes. Not an all-learning-off switch or evidence of learning gains.' }
    File.write(File.join(output, 'experiments.json'), JSON.pretty_generate(report))
    report
  end
end

if $PROGRAM_NAME == __FILE__
  report = HarnessExperiments.run(output: ARGV.fetch(0), manifest: ARGV[1], gold: ARGV[2], frozen: ARGV[3])
  puts JSON.pretty_generate(report)
  exit(report[:snapshot_unchanged] && report[:input_manifests_unchanged] && report[:results].all? { |row| row[:outcome] == 'PASS' && row[:inputs_unchanged] && !row[:false_success] && row[:repeated_effects].zero? } ? 0 : 1)
end
