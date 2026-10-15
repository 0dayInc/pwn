# frozen_string_literal: true

require 'json'
require 'digest'
require 'open3'
require 'fileutils'
require 'tmpdir'
require 'rbconfig'
require 'timeout'

# Offline only. The separate opt-in reference adapter cannot be selected here.
module HarnessEvaluation
  ROOT = File.expand_path('../../..', __dir__)
  MANIFEST = File.join(ROOT, 'spec/fixtures/harness/manifest.json')

  # Scripted shell tasks call `ruby`. A stripped PATH must still find the suite
  # interpreter: /usr/bin/ruby may be older or lack json, which fails only the
  # held-out JSON task while File-only tasks pass.
  def self.isolated_path
    [File.dirname(RbConfig.ruby), '/usr/bin', '/bin'].uniq.join(File::PATH_SEPARATOR)
  end

  def self.validate_parity!(left, right)
    fields = %w[provider model revision endpoint reasoning temperature max_iterations max_tokens wall_seconds tool_capabilities network]
    fields.each do |key|
      [left, right].each do |config|
        value = config[key]
        raise ArgumentError, "unknown comparison field: #{key}" if value.nil? || value.to_s.strip.empty? || %w[unknown unselected latest].include?(value.to_s.downcase)
      end
      raise ArgumentError, "comparison mismatch: #{key}" unless left[key] == right[key]
    end
    :validated
  end

  # This host checker has no access to provider assertions or runtime verdicts.
  def self.grade(task, root, result)
    checks = task.fetch('checks').map do |check|
      path = File.expand_path(check.fetch('path'), root)
      raise ArgumentError, 'check escapes task workspace' unless path.start_with?("#{File.expand_path(root)}/")

      safe = File.file?(path) && !File.symlink?(path) && File.realpath(path).start_with?("#{File.realpath(root)}/")
      bytes = safe ? File.binread(path) : nil
      { path: path, passed: bytes == check.fetch('bytes'), observed_sha256: bytes && Digest::SHA256.hexdigest(bytes) }
    end
    claimed = result.fetch(:stdout).include?(task.fetch('success_marker'))
    passed = !checks.empty? && checks.all? { |row| row[:passed] } && result[:exit_status]&.zero? && claimed
    effects_path = File.join(root, 'effects.log')
    effects = File.file?(effects_path) ? File.readlines(effects_path, chomp: true) : []
    tools_path = File.join(root, 'events.jsonl.tools')
    tools = File.file?(tools_path) ? File.readlines(tools_path, encoding: Encoding::UTF_8).map { |line| JSON.parse(line) } : []
    timeouts = tools.count do |row|
      envelope = row['result']
      next false unless envelope.is_a?(Hash)

      [envelope, envelope['result']].any? do |value|
        value.is_a?(Hash) && (value['error'] == 'timeout' || (value['scenario'] == 'deadline' && value['error'].to_s.start_with?('timeout after ')))
      end
    end
    outcome = if result[:resource_cap] || (!passed && timeouts.positive?)
                'INCOMPLETE'
              else
                passed ? 'PASS' : 'FAIL'
              end
    { outcome: outcome, checks: checks, tool_timeouts: timeouts,
      false_success: claimed && !checks.all? { |row| row[:passed] },
      repeated_effects: effects.tally.values.sum { |count| count - 1 }, observed_effects: effects }
  end

  def self.capture(env, command, cwd, seconds, controls = {})
    ready_path = controls[:ready_path]
    startup_seconds = controls.fetch(:startup_seconds, 35)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    stdout = stderr = ''
    status = nil
    capped = false
    ready_observed = false
    Open3.popen3(env, *command, chdir: cwd, unsetenv_others: true, pgroup: true) do |input, output, error, waiter|
      input.close
      output.set_encoding(Encoding::UTF_8)
      error.set_encoding(Encoding::UTF_8)
      readers = [Thread.new { output.read }, Thread.new { error.read }]
      begin
        if ready_path
          Timeout.timeout(startup_seconds) do
            sleep 0.02 until File.file?(ready_path) || !waiter.alive?
          end
          ready_observed = File.file?(ready_path)
        end
        Timeout.timeout(seconds) do
          status = waiter.value
          stdout, stderr = readers.map(&:value)
        end
      rescue Timeout::Error
        capped = true
        begin
          Process.kill('KILL', -waiter.pid)
        rescue Errno::ESRCH
          nil
        end
        status = waiter.value
        stdout, stderr = readers.map(&:value)
      end
    end
    { stdout: stdout, stderr: stderr, exit_status: status.exitstatus,
      signal: status.termsig, resource_cap: capped, ready_observed: ready_observed,
      latency_seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started }
  end

  # Gem activation is not part of the scripted work cap. Packaged boots get a
  # separate finite startup bound; a missing ready file is a capped boot, not a parser crash.
  def self.agent_capture(env, command, cwd, seconds, options = {})
    ready = File.join(cwd, 'harness-ready')
    startup = options[:executable] ? 180 : 45
    capture(env.merge('PWN_HARNESS_READY' => ready), command, cwd, seconds, ready_path: ready, startup_seconds: startup)
  end

  def self.run(options)
    manifest_path = options[:source_root] ? File.join(options[:source_root], 'spec/fixtures/harness/manifest.json') : MANIFEST
    manifest_bytes = File.binread(manifest_path)
    manifest = JSON.parse(manifest_bytes)
    lock = File.read("#{manifest_path}.sha256").strip
    raise 'manifest hash mismatch' unless Digest::SHA256.hexdigest(manifest_bytes) == lock

    adapter_path = File.join(File.dirname(manifest_path), 'adapters.json')
    adapter_lock = File.read("#{adapter_path}.sha256").strip
    raise 'adapter hash mismatch' unless Digest::SHA256.file(adapter_path).hexdigest == adapter_lock

    output_root = options.fetch(:output)
    FileUtils.mkdir_p(output_root)
    ruby = RbConfig.ruby
    rows = manifest.fetch('tasks').map do |task|
      root = Dir.mktmpdir("#{task.fetch('id')}-", output_root)
      home = File.join(root, 'home')
      FileUtils.mkdir_p(home)
      fixture = File.join(root, 'provider.json')
      File.write(fixture, JSON.generate(responses: task.fetch('responses')))
      events = File.join(root, 'events.jsonl')
      fingerprint = File.join(root, 'fingerprint.json')
      env = { 'HOME' => home, 'PATH' => isolated_path, 'LANG' => 'C.UTF-8',
              'GEM_HOME' => options[:gem_home] || Gem.dir,
              'GEM_PATH' => options[:gem_path] || Gem.path.join(File::PATH_SEPARATOR),
              'PWN_HARNESS_FIXTURE' => fixture, 'PWN_HARNESS_EVENTS' => events,
              'PWN_HARNESS_FINGERPRINT' => fingerprint }
      executable = options[:executable] || File.join(ROOT, 'bin/pwn-ai')
      preload = File.join(options[:source_root] || ROOT, 'spec/support/harness/fake_provider.rb')
      command = [ruby]
      command += ['-I', File.join(ROOT, 'lib')] unless options[:executable]
      command += ['-r', preload, executable, '--ai', task.fetch('prompt')]
      result = HarnessEvaluation.agent_capture(env, command, root, manifest.fetch('budget').fetch('wall_seconds'), options)
      grade = grade(task, root, result)
      File.write(File.join(root, 'stdout.txt'), result.delete(:stdout))
      File.write(File.join(root, 'stderr.txt'), result.delete(:stderr))
      trace = File.file?(events) ? File.readlines(events, encoding: Encoding::UTF_8).map { |line| JSON.parse(line) } : []
      { task: task.fetch('id'), domain: task.fetch('domain'), lane: 'offline_scripted_provider',
        expected_outcome: task.fetch('expected_outcome'), interventions: 0,
        provider_calls: trace.size, execution_counts: { single: 1, swarm: 0, learning: nil, policy: 0 },
        effect_observation_scope: 'effects.log fixture marker only; general tool side effects not counted',
        tokens: nil, cost: nil, usage_status: 'unknown: fake provider does not report tokens or bill',
        artifact_root: root, command: command }.merge(result).merge(grade)
    end
    fault_root = Dir.mktmpdir('runtime-faults-', output_root)
    fault_env = { 'HOME' => fault_root, 'PATH' => isolated_path, 'LANG' => 'C.UTF-8',
                  'GEM_HOME' => options[:gem_home] || Gem.dir,
                  'GEM_PATH' => options[:gem_path] || Gem.path.join(File::PATH_SEPARATOR) }
    fault_source = options[:source_root] || ROOT
    fault_run = capture(fault_env, [ruby, '-I', File.join(fault_source, 'lib'),
                                    File.join(fault_source, 'spec/support/harness/runtime_faults.rb'), fault_root], fault_root, 30)
    File.write(File.join(fault_root, 'process.json'), JSON.pretty_generate(fault_run))
    faults = begin
      JSON.parse(fault_run[:stdout])
    rescue JSON::ParserError
      { outcome: fault_run[:resource_cap] ? 'INCOMPLETE' : 'ERROR', artifact_root: fault_root }
    end
    require_relative 'cli_faults'
    require_relative 'experiments'
    require_relative 'swarm_acceptance'
    require_relative 'session_acceptance'
    cli_faults = HarnessCLIFaults.run(options.merge(output: File.join(output_root, 'cli-faults')))
    experiments = HarnessExperiments.run(options.merge(output: File.join(output_root, 'experiments')))
    swarm_acceptance = HarnessSwarmAcceptance.run(options.merge(output: File.join(output_root, 'swarm-acceptance')))
    session_acceptance = HarnessSessionAcceptance.run(options.merge(output: File.join(output_root, 'session-acceptance')))
    report = { schema: 'pwn-harness-evaluation-v2', manifest_sha256: lock, adapters_sha256: adapter_lock,
               environment: { ruby: RUBY_DESCRIPTION, platform: RUBY_PLATFORM, dependencies: Gem.loaded_specs.transform_values(&:version).transform_values(&:to_s) },
               runtime_faults: faults, runtime_fault_process: fault_run.slice(:exit_status, :resource_cap),
               cli_faults: cli_faults, experiments: experiments, swarm_acceptance: swarm_acceptance, session_acceptance: session_acceptance, model_quality: 'NOT_RUN',
               model_comparison: { outcome: 'NOT_RUN', reason: 'No live budget approved; pinned model and adapter parity pending.' },
               ablations: manifest.fetch('ablations'), faults_pending: manifest.fetch('faults_pending'), results: rows }
    File.write(File.join(output_root, 'results.json'), JSON.pretty_generate(report))
    report
  end
end
