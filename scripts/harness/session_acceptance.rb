# frozen_string_literal: true

require_relative 'experiments'

# Public CLI selection/approval, no injected runtime or fabricated receipts.
module HarnessSessionAcceptance
  def self.invoke(root, steps, args, options)
    source = options[:source_root] || HarnessEvaluation::ROOT
    FileUtils.mkdir_p(File.join(root, 'home'))
    File.write(File.join(root, 'provider.json'), JSON.generate(responses: steps))
    env = { 'HOME' => File.join(root, 'home'), 'PATH' => '/usr/bin:/bin', 'LANG' => 'C.UTF-8',
            'GEM_HOME' => options[:gem_home] || Gem.dir, 'GEM_PATH' => options[:gem_path] || Gem.path.join(File::PATH_SEPARATOR),
            'PWN_HARNESS_FIXTURE' => File.join(root, 'provider.json'), 'PWN_HARNESS_EVENTS' => File.join(root, 'events.jsonl'),
            'PWN_HARNESS_FINGERPRINT' => File.join(root, 'fingerprint.json') }
    command = [RbConfig.ruby]
    command += ['-I', File.join(source, 'lib')] unless options[:executable]
    command += ['-r', File.join(source, 'scripts/harness/fake_provider.rb'), options[:executable] || File.join(source, 'bin/pwn-ai')] + args
    HarnessEvaluation.capture(env, command, root, 35).merge(command: command)
  end

  def self.run(options)
    FileUtils.mkdir_p(options.fetch(:output))
    final = { role: 'assistant', content: 'FIXTURE_COMPLETE', tool_calls: [] }
    rows = %w[resume replacement].map do |name|
      root = Dir.mktmpdir("session-#{name}-", options.fetch(:output))
      prompt = 'Create result.txt containing exactly alpha followed by newline, then read it back.'
      contract = { requirements: [prompt], root: root, checks: [{ requirement: prompt, kind: 'file', path: 'result.txt', expected: "alpha\n" }] }
      contract_path = File.join(root, 'contract.json')
      File.write(contract_path, JSON.generate(contract))
      initial = invoke(root, [HarnessExperiments.tool('shell', { command: "printf 'wrong\\n' > result.txt", timeout: 10 }, 'wrong')] + Array.new(8) { final },
                       ['--ai', prompt, '--verification-contract', contract_path], options)
      old_path = Dir.glob(File.join(root, 'home/.pwn/sessions/requests/**/*.json')).fetch(0)
      old_bytes = File.binread(old_path)
      old = JSON.parse(old_bytes)
      sid = old.fetch('session_id')
      args = ['--resume-session', sid]
      wanted = 'alpha'
      if name == 'replacement'
        wanted = 'beta'
        prompt = prompt.sub('alpha', 'beta')
        contract = { requirements: [prompt], root: root, checks: [{ requirement: prompt, kind: 'file', path: 'result.txt', expected: "beta\n" }] }
        File.write(contract_path, JSON.generate(contract))
        args = ['--replace-session', sid, '--ai', prompt, '--verification-contract', contract_path, '--approve-replacement']
      end
      steps = [HarnessExperiments.tool('shell', { command: "printf '#{wanted}\\n' > result.txt", timeout: 10 }, 'repair'),
               HarnessExperiments.tool('shell', { command: 'cat result.txt', timeout: 10 }, 'read'), final]
      result = invoke(root, steps, args, options)
      paths = Dir.glob(File.join(root, 'home/.pwn/sessions/requests/**/*.json'))
      latest = paths.map { |path| JSON.parse(File.read(path)) }.find { |row| row.dig('outcome', 'status') == 'complete' }
      identity = if name == 'resume'
                   paths.length == 1 && latest && latest['request_id'] == old['request_id'] && latest['original_request'] == old['original_request'] && latest['verification_contract'] == old['verification_contract']
                 else
                   paths.length == 2 && File.binread(old_path) == old_bytes && latest && latest['request_id'] != old['request_id'] && latest['original_request'] == prompt
                 end
      passed = initial[:exit_status] == 1 && result[:exit_status]&.zero? && identity && File.read(File.join(root, 'result.txt')) == "#{wanted}\n"
      File.write(File.join(root, 'process.json'), JSON.pretty_generate(initial: initial, selected: result))
      { id: name, outcome: passed ? 'PASS' : 'FAIL', initial_exit_status: initial[:exit_status], exit_status: result[:exit_status],
        identity_preserved: identity ? true : false, artifact_root: root, task_outcome: latest&.fetch('outcome', nil) }
    end
    report = { results: rows, model_quality: 'NOT_RUN' }
    File.write(File.join(options.fetch(:output), 'session-acceptance.json'), JSON.pretty_generate(report))
    report
  end
end

if $PROGRAM_NAME == __FILE__
  report = HarnessSessionAcceptance.run(output: ARGV.fetch(0))
  puts JSON.pretty_generate(report)
  exit(report[:results].all? { |row| row[:outcome] == 'PASS' } ? 0 : 1)
end
