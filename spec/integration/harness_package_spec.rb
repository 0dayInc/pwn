# frozen_string_literal: true

require 'spec_helper'
require_relative '../support/harness/package_acceptance'

RSpec.describe 'installed gem harness acceptance' do
  it 'checks the isolated installation against the independently probed kernel capability' do
    reason = PwnSpecLandlock.unavailable_reason
    Dir.mktmpdir('pwn-package-spec-', '/tmp') do |root|
      report = HarnessPackageAcceptance.run(output: root, landlock_unavailable_reason: reason)
      package = report.fetch(:package)
      expect(package).to include(installed_source_mismatches: [], source_changes_during_run: [])
      expect(report.fetch(:runtime_fault_process)).to include(exit_status: 0, resource_cap: false)
      expect(report.fetch(:runtime_faults).fetch('results').map { |row| row.fetch('id') }).to eq(%w[compaction-preserves-goal-and-steering resource-cap-checkpoint-recovery retry-provider-fallback-before-effects cancel-blocked-provider])
      expect(report.fetch(:runtime_faults).fetch('results')).to all(include('outcome' => 'PASS'))
      if reason
        expect(report.fetch(:behavioral_evaluation)).to eq(outcome: 'NOT_RUN', reason: reason)
        rejection = report.fetch(:sandbox_rejection)
        installed = package.fetch(:installed_root)
        expect(rejection).to include(outcome: 'NOT_STARTED', activated_gem_root: installed, sandbox_source: File.join(installed, 'lib/pwn/ai/sandbox.rb'))
        expect(File.exist?(File.join(rejection.fetch(:artifact_root), 'marker'))).to be(false)
        next
      end

      expect(report.fetch(:results).map { |row| row.fetch(:task) }).to contain_exactly('coding', 'exact-file', 'security-toy', 'structured', 'artifact-lie', 'timeout-replay')
      report.fetch(:results).each do |row|
        expect(row).to include(outcome: row.fetch(:expected_outcome), false_success: false, repeated_effects: 0)
        expect(row.fetch(:command)).to include(File.join(File.dirname(report.dig(:package, :installed_root)), '..', 'bin/pwn-ai').then { |path| File.expand_path(path) })
      end
      expect(report.fetch(:cli_faults).fetch(:results).map { |row| row.fetch(:id) }).to eq(%w[compaction-steering provider-retry cancel-during-provider checkpoint-restart resource-cap-restart])
      expect(report.fetch(:cli_faults).fetch(:results)).to all(include(outcome: 'PASS', repeated_effects: 0))
      expect(report.fetch(:swarm_acceptance).fetch(:results).map { |row| row.fetch(:id) }).to eq(%w[correct lie stale missing tampered])
      expect(report.fetch(:swarm_acceptance).fetch(:results)).to all(include(outcome: 'PASS'))
      expect(report.fetch(:swarm_acceptance).fetch(:results).drop(1)).to all(include(exit_status: 1))
      expect(report.fetch(:session_acceptance).fetch(:results).map { |row| row.fetch(:id) }).to eq(%w[resume replacement])
      expect(report.fetch(:session_acceptance).fetch(:results)).to all(include(outcome: 'PASS', identity_preserved: true))
      experiments = report.fetch(:experiments)
      expect(experiments).to include(snapshot_unchanged: true, input_manifests_unchanged: true)
      expect(experiments.fetch(:training).length).to eq(1)
      expect(experiments.fetch(:results).length).to eq(8)
      expect(experiments.fetch(:training) + experiments.fetch(:results)).to all(include(outcome: 'PASS', inputs_unchanged: true, false_success: false, repeated_effects: 0))
      expect(experiments.fetch(:results).select { |row| row[:arm] == 'swarm-snapshot' }).to all(include(nested_provider_calls: 3))
      expect(experiments.fetch(:results).select { |row| row[:arm] == 'single-policy' }.map { |row| row[:policy_episodes] }).to all(be > 0)
      expect(report.fetch(:model_comparison)).to include(outcome: 'NOT_RUN')
    ensure
      Dir.glob(File.join(root, '**', '*'), File::FNM_DOTMATCH).each { |path| File.chmod(0o700, path) if File.directory?(path) }
    end
  end
end
