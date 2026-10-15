# frozen_string_literal: true

require_relative 'evaluate' unless defined?(HarnessEvaluation)

# Adversarial provider stimuli around the real one-shot executable.
module HarnessCLIFaults
  def self.tool(command, id = 'tool', timeout = 10)
    { role: 'assistant', tool_calls: [{ id: id, type: 'function', function: {
      name: 'shell', arguments: JSON.generate(command: command, timeout: timeout)
    } }] }
  end

  def self.invoke(root, fixture, prompt, options)
    FileUtils.mkdir_p(File.join(root, 'home'))
    path = File.join(root, 'provider.json')
    File.write(path, JSON.generate(fixture))
    source = options[:source_root] || HarnessEvaluation::ROOT
    env = { 'HOME' => File.join(root, 'home'), 'PATH' => HarnessEvaluation.isolated_path, 'LANG' => 'C.UTF-8',
            'GEM_HOME' => options[:gem_home] || Gem.dir, 'GEM_PATH' => options[:gem_path] || Gem.path.join(File::PATH_SEPARATOR),
            'PWN_HARNESS_FIXTURE' => path, 'PWN_HARNESS_EVENTS' => File.join(root, 'events.jsonl'),
            'PWN_HARNESS_FINGERPRINT' => File.join(root, 'fingerprint.json'), 'PWN_HARNESS_RUNTIME' => File.join(root, 'runtime'),
            'PWN_HARNESS_CAP_READY' => File.join(root, 'cap-ready') }
    command = [RbConfig.ruby]
    command += ['-I', File.join(source, 'lib')] unless options[:executable]
    command += ['-r', File.join(source, 'spec/support/harness/fault_preload.rb'),
                options[:executable] || File.join(source, 'bin/pwn-ai'), '--ai', prompt]
    ready_path = fixture[:await_cap_ready] ? env.fetch('PWN_HARNESS_CAP_READY') : nil
    startup = options[:executable] ? 180 : 45
    report = if ready_path
               HarnessEvaluation.capture(env, command, root, fixture.fetch(:wall_seconds, 35), ready_path: ready_path, startup_seconds: startup)
             else
               HarnessEvaluation.agent_capture(env, command, root, fixture.fetch(:wall_seconds, 35), options)
             end
    phase = fixture[:resume] ? 'resumed' : 'initial'
    File.write(File.join(root, "#{phase}-process.json"), JSON.pretty_generate(report.merge(command: command)))
    report
  end

  def self.run(options)
    FileUtils.mkdir_p(options.fetch(:output))
    rows = []
    final = { role: 'assistant', content: 'FIXTURE_COMPLETE', tool_calls: [] }
    %w[compaction-steering provider-retry cancel-during-provider checkpoint-restart resource-cap-restart].each do |name|
      root = Dir.mktmpdir("#{name}-", options.fetch(:output))
      prompt = 'Create result.txt containing exactly alpha followed by newline, then read it back.'
      write = tool("printf 'alpha\\n' > result.txt; printf 'result-write\\n' >> effects.log", 'write')
      read = tool('cat result.txt', 'read')
      fixture = { responses: [write, read, final] }
      case name
      when 'compaction-steering'
        fixture[:window] = 200
        fixture[:steer_after_tools] = 6
        fixture[:steer] = 'Also create latest.txt containing exactly beta followed by newline and read it back.'
        fixture[:agent] = { max_iters: 16 }
        fixture[:responses] = [write, read] + 4.times.map { |i| tool("cat result.txt; printf '#{'context ' * 300}'", "context-#{i}") } +
                              [tool("printf 'beta\\n' > latest.txt; printf 'latest-write\\n' >> effects.log", 'latest'), tool('cat result.txt latest.txt', 'verify'), final]
      when 'provider-retry'
        fixture[:responses] = [write, { fault: 'retry' }, read, final]
      when 'cancel-during-provider'
        fixture[:responses] = [write, { fault: 'cancel' }]
      when 'checkpoint-restart', 'resource-cap-restart'
        prompt = 'Create result.txt after the operation completes and read it back.'
        write = tool("printf 'uncertain-write\\n' >> effects.log; sleep 3; printf done > result.txt", 'uncertain', 1)
        fixture[:responses] = [write, { fault: name == 'checkpoint-restart' ? 'crash' : 'resource_cap' }]
        fixture.merge!(wall_seconds: 4, await_cap_ready: true) if name == 'resource-cap-restart'
      end
      result = invoke(root, fixture, prompt, options)
      first = result.dup
      if %w[checkpoint-restart resource-cap-restart].include?(name)
        fixture = { resume: true, responses: [write, final] }
        result = invoke(root, fixture, 'continue', options)
      end
      observed_path = File.join(root, 'runtime', 'runtime-observed.json')
      observed = File.file?(observed_path) ? JSON.parse(File.read(observed_path)) : {}
      events_path = File.join(root, 'events.jsonl')
      trace = File.file?(events_path) ? File.readlines(events_path, encoding: Encoding::UTF_8).map { |line| JSON.parse(line) } : []
      effects = File.file?(File.join(root, 'effects.log')) ? File.readlines(File.join(root, 'effects.log'), chomp: true) : []
      bytes = File.file?(File.join(root, 'result.txt')) ? File.read(File.join(root, 'result.txt')) : nil
      passed = case name
               when 'compaction-steering'
                 result[:exit_status]&.zero? && bytes == "alpha\n" && File.read(File.join(root, 'latest.txt')) == "beta\n" &&
                 effects == %w[result-write latest-write] && observed.fetch('effective').include?('Also create latest.txt') &&
                 trace.any? { |row| JSON.generate(row['messages']).include?('ENGAGEMENT MEMORY') }
               when 'provider-retry'
                 result[:exit_status]&.zero? && bytes == "alpha\n" && effects == ['result-write'] && trace.length == 4
               when 'cancel-during-provider'
                 result[:exit_status] == 1 && bytes == "alpha\n" && effects == ['result-write'] &&
                 observed.dig('outcome', 'status') == 'cancelled' && trace.length == 2 && !result[:stdout].include?('FIXTURE_COMPLETE')
               when 'checkpoint-restart', 'resource-cap-restart'
                 (name == 'checkpoint-restart' ? first[:exit_status] == 73 : first[:resource_cap] && first[:ready_observed]) &&
                 result[:exit_status] == 1 && effects == ['uncertain-write'] && bytes.nil? &&
                 observed.dig('outcome', 'status') != 'complete' &&
                 observed.fetch('events').one? { |row| row['phase'] == 'start' && row['tool'] == 'shell' }
               end
      outcome = if result[:resource_cap]
                  'INCOMPLETE'
                else
                  passed ? 'PASS' : 'FAIL'
                end
      rows << { id: name, outcome: outcome,
                task_outcome: observed['outcome'], exit_status: result[:exit_status], initial_exit_status: first[:exit_status],
                initial_resource_cap: first[:resource_cap], initial_outcome: first[:resource_cap] ? 'INCOMPLETE' : nil,
                cap_ready_observed: first[:ready_observed], cap_startup_bound_seconds: name == 'resource-cap-restart' ? 35 : nil,
                effects: effects, repeated_effects: effects.tally.values.sum { |n| n - 1 }, provider_calls: trace.length,
                artifact_root: root, tokens: nil, cost: nil,
                boundary: 'actual CLI with test-injected public Loop runtime/steering controls; provider fake, tools real' }
    end
    report = { schema: 'pwn-cli-faults-v1', model_quality: 'NOT_RUN', results: rows }
    File.write(File.join(options.fetch(:output), 'cli-faults.json'), JSON.pretty_generate(report))
    report
  end
end
