# frozen_string_literal: true

require_relative 'evaluate'

# Isolated build/install driver. Acceptance belongs to RSpec, not process exit.
module HarnessPackageAcceptance
  def self.run(options)
    root = options.fetch(:output)
    FileUtils.mkdir_p(root)
    root = Dir.mktmpdir('acceptance-', root)
    snapshot = File.join(root, 'source')
    home = File.join(root, 'home')
    gem_home = File.join(root, 'gems')
    [snapshot, home, gem_home].each { |path| FileUtils.mkdir_p(path) }
    paths, error, status = Open3.capture3('git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard', chdir: HarnessEvaluation::ROOT)
    raise error unless status.success?

    ledger = {}
    paths.split("\0").uniq.each do |relative|
      source = File.join(HarnessEvaluation::ROOT, relative)
      next unless File.file?(source)
      raise "snapshot symlink refused: #{relative}" if File.symlink?(source)

      target = File.join(snapshot, relative)
      FileUtils.mkdir_p(File.dirname(target))
      FileUtils.cp(source, target)
      ledger[relative] = Digest::SHA256.file(target).hexdigest
    end
    File.write(File.join(root, 'source-sha256.json'), JSON.pretty_generate(ledger))
    changed = ledger.keys.reject do |relative|
      source = File.join(HarnessEvaluation::ROOT, relative)
      File.file?(source) && Digest::SHA256.file(source).hexdigest == ledger.fetch(relative)
    end
    raise "source changed during snapshot; retry after integration settles: #{changed.inspect}" unless changed.empty?

    # An independent scratch index is needed by the project's git-based gemspec;
    # neither the working checkout's index nor its installed gem is changed.
    env = { 'HOME' => home, 'PATH' => ENV.fetch('PATH'), 'LANG' => 'C.UTF-8',
            'GEM_HOME' => gem_home, 'GEM_PATH' => Gem.path.join(File::PATH_SEPARATOR) }
    commands = [
      ['git', 'init', '-q'], ['git', 'add', '--all'],
      [RbConfig.ruby, '-S', 'gem', 'build', 'pwn.gemspec', '--output', File.join(root, 'pwn.gem')],
      [RbConfig.ruby, '-S', 'gem', 'install', '--local', '--ignore-dependencies', '--no-document', '--install-dir', gem_home, File.join(root, 'pwn.gem')]
    ]
    commands.each_with_index do |command, index|
      result = HarnessEvaluation.capture(env, command, snapshot, 120)
      File.write(File.join(root, "build-#{index}.json"), JSON.pretty_generate(result))
      raise "package step failed: #{command.inspect}; #{root}/build-#{index}.json; #{process_evidence(result.merge(artifact_root: root))}" unless result[:exit_status]&.zero?
    end
    installed = Dir.glob(File.join(gem_home, 'gems/pwn-*')).fetch(0)
    installed_mismatches = ledger.keys.select { |relative| relative.start_with?('lib/', 'bin/', 'spec/support/harness/', 'spec/fixtures/harness/') }.reject do |relative|
      path = File.join(installed, relative)
      File.file?(path) && Digest::SHA256.file(path).hexdigest == ledger.fetch(relative)
    end
    raise "installed source differs from snapshot: #{installed_mismatches.inspect}" unless installed_mismatches.empty?

    report = HarnessEvaluation.run(output: File.join(root, 'runs'), gem_home: gem_home,
                                   gem_path: ([gem_home] + Gem.path).join(File::PATH_SEPARATOR),
                                   source_root: installed, executable: File.join(gem_home, 'bin/pwn-ai'))
    report[:package] = { installed_root: installed, sha256: Digest::SHA256.file(File.join(root, 'pwn.gem')).hexdigest,
                         installed_source_mismatches: installed_mismatches,
                         source_ledger: File.join(root, 'source-sha256.json'),
                         dependencies: 'Existing dependency gems read-only; this is not a clean dependency-install test.' }
    report[:package][:source_changes_during_run] = ledger.keys.reject do |relative|
      source = File.join(HarnessEvaluation::ROOT, relative)
      File.file?(source) && Digest::SHA256.file(source).hexdigest == ledger.fetch(relative)
    end
    rows = report[:results] + report[:cli_faults][:results] + report[:experiments][:training] + report[:experiments][:results] + report[:swarm_acceptance][:results] + report[:session_acceptance][:results]
    File.write(File.join(root, 'acceptance.json'), JSON.pretty_generate(report))
    validate_fingerprints!(rows, installed)
    report
  end

  def self.validate_fingerprints!(rows, installed)
    rows.each do |row|
      path = File.join(row.fetch(:artifact_root), 'fingerprint.json')
      begin
        fingerprint = JSON.parse(File.read(path))
        components = fingerprint.fetch('components')
        raise KeyError, 'empty component inventory' unless components.is_a?(Array) && !components.empty?
      rescue SystemCallError, JSON::ParserError, KeyError => e
        raise "#{row[:id] || row[:task]}: missing or invalid fingerprint #{path} (#{e.class}); child evidence: #{process_evidence(row)}"
      end
      wrong = components.reject { |item| item.fetch('path').start_with?("#{installed}/lib/") }
      raise "loaded another PWN deployment: #{wrong.inspect}" unless wrong.empty?
    end
  end

  def self.process_evidence(row)
    require 'pwn'
    root = row.fetch(:artifact_root)
    evidence = { result: row }
    Dir.glob(File.join(root, '*process.json')).each do |path|
      evidence[File.basename(path)] = JSON.parse(File.read(path))
    rescue JSON::ParserError
      evidence[File.basename(path)] = 'invalid process JSON; inspect artifact'
    end
    %w[stdout stderr].each do |stream|
      path = File.join(root, "#{stream}.txt")
      evidence[stream] = File.read(path) if File.file?(path)
    end
    # Redact before truncating so a cut cannot expose a partial credential.
    JSON.generate(PWN::Redaction.redact(value: evidence))[0, 16_384]
  end
end
