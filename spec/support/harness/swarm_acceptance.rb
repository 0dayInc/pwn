# frozen_string_literal: true

require_relative 'experiments'

# Real delegation, real shell effects; only the provider is scripted.
module HarnessSwarmAcceptance
  def self.run(options)
    FileUtils.mkdir_p(options.fetch(:output))
    source = options[:source_root] || HarnessEvaluation::ROOT
    rows = %w[correct lie stale missing tampered].map do |name|
      root = Dir.mktmpdir("swarm-#{name}-", options.fetch(:output))
      home = File.join(root, 'home')
      FileUtils.mkdir_p(home)
      prompt = 'Create result.txt containing exactly alpha followed by newline, then read it back.'
      final = { role: 'assistant', content: 'FIXTURE_COMPLETE', tool_calls: [] }
      steps = [HarnessExperiments.tool('agent_spawn', { name: 'fixture_worker', role: 'Execute assigned fixture with tools.', toolsets: ['shell'], engine: 'openai', model: 'offline-scripted-v1', max_iters: 4 }, 'spawn'),
               HarnessExperiments.tool('agent_ask', { name: 'fixture_worker', request: prompt }, 'ask')]
      File.write(File.join(root, 'result.txt'), "alpha\n") if name == 'stale'
      unless %w[stale missing].include?(name)
        bytes = name == 'lie' ? 'wrong' : 'alpha'
        steps << HarnessExperiments.tool('shell', { command: "printf '#{bytes}\\n' > result.txt", timeout: 10 }, 'child-write')
        steps << HarnessExperiments.tool('shell', { command: 'cat result.txt', timeout: 10 }, 'child-read')
      end
      if %w[correct tampered].include?(name)
        steps << final
        command = name == 'tampered' ? "printf 'changed\\n' > result.txt; cat result.txt" : 'cat result.txt'
        steps << HarnessExperiments.tool('shell', { command: command, timeout: 10 }, 'parent-check')
      end
      steps += Array.new(16) { final }
      fixture = File.join(root, 'provider.json')
      File.write(fixture, JSON.generate(responses: steps, toolsets: %w[shell swarm], agent: { max_iters: 6 }))
      env = { 'HOME' => home, 'PATH' => '/usr/bin:/bin', 'LANG' => 'C.UTF-8',
              'GEM_HOME' => options[:gem_home] || Gem.dir, 'GEM_PATH' => options[:gem_path] || Gem.path.join(File::PATH_SEPARATOR),
              'PWN_HARNESS_FIXTURE' => fixture, 'PWN_HARNESS_EVENTS' => File.join(root, 'events.jsonl'),
              'PWN_HARNESS_FINGERPRINT' => File.join(root, 'fingerprint.json') }
      command = [RbConfig.ruby]
      command += ['-I', File.join(source, 'lib')] unless options[:executable]
      command += ['-r', File.join(source, 'spec/support/harness/fake_provider.rb'), options[:executable] || File.join(source, 'bin/pwn-ai'), '--ai', prompt]
      result = HarnessEvaluation.capture(env, command, root, 35)
      File.write(File.join(root, 'process.json'), JSON.pretty_generate(result.merge(command: command)))
      checkpoints = Dir.glob(File.join(home, '.pwn/sessions/requests/**/*.json')).map { |path| JSON.parse(File.read(path)) }
      parent = checkpoints.find { |row| Array(row['enabled_toolsets']).include?('swarm') }
      receipt = parent&.dig('observations', File.join(root, 'result.txt'))
      child = checkpoints.find { |row| row['request_id'] == receipt&.fetch('child_request_id', nil) }
      bytes = File.file?(File.join(root, 'result.txt')) ? File.read(File.join(root, 'result.txt')) : nil
      passed = if name == 'correct'
                 result[:exit_status]&.zero? && bytes == "alpha\n" && parent && parent.dig('outcome', 'status') == 'complete' &&
                   child && receipt['artifact_turn_id'] == parent['request_id'] && receipt['child_turn_id'] == child['request_id'] &&
                   receipt['sha256'] == Digest::SHA256.hexdigest("alpha\n") && child.dig('outcome', 'status') == 'complete'
               else
                 result[:exit_status] == 1 && parent && parent.dig('outcome', 'status') != 'complete' && !result[:stdout].include?('FIXTURE_COMPLETE')
               end
      { id: name, outcome: passed ? 'PASS' : 'FAIL', task_outcome: parent&.fetch('outcome', nil),
        exit_status: result[:exit_status], artifact_root: root, bytes: bytes,
        boundary: 'actual CLI agent_spawn/agent_ask/nested Loop, host receipts and parent check; scripted provider, no live quality claim' }
    end
    report = { results: rows, model_quality: 'NOT_RUN' }
    File.write(File.join(options.fetch(:output), 'swarm-acceptance.json'), JSON.pretty_generate(report))
    report
  end
end
