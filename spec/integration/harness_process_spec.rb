# frozen_string_literal: true

require 'spec_helper'
require_relative '../support/harness/package_acceptance'
require_relative '../support/harness/cli_faults'

RSpec.describe 'harness process lifecycle' do
  it 'preserves actual exit and stderr when startup fails before readiness' do
    Dir.mktmpdir('pwn-harness-process-') do |root|
      ready = File.join(root, 'ready')
      command = [RbConfig.ruby, '-e', "warn 'unsupported architecture fixture'; exit 78"]
      result = HarnessEvaluation.capture({ 'HOME' => root }, command, root, 1, ready_path: ready, startup_seconds: 2)
      expect(result).to include(exit_status: 78, stderr: "unsupported architecture fixture\n", resource_cap: false, ready_observed: false, timeout_phase: nil)
    end
  end

  it 'distinguishes a bounded boot timeout from an execution timeout' do
    Dir.mktmpdir('pwn-harness-process-') do |root|
      result = HarnessEvaluation.capture({ 'HOME' => root }, [RbConfig.ruby, '-e', 'sleep 60'], root, 1,
                                         ready_path: File.join(root, 'ready'), startup_seconds: 0.05)
      expect(result).to include(resource_cap: true, ready_observed: false, timeout_phase: 'startup', exit_status: nil, signal: Signal.list.fetch('KILL'))
    end
  end

  it 'reports the real child failure when its fingerprint is missing, without inventing one' do
    Dir.mktmpdir('pwn-harness-process-') do |root|
      process = HarnessEvaluation.capture({ 'HOME' => root }, [RbConfig.ruby, '-e', "warn 'namespace unavailable'; exit 78"], root, 2)
      File.write(File.join(root, 'initial-process.json'), JSON.generate(process))
      row = { id: 'checkpoint-restart', artifact_root: root }
      expect { HarnessPackageAcceptance.validate_fingerprints!([row], '/isolated/gems/pwn') }
        .to raise_error(RuntimeError) { |error| expect(error.message).to include('checkpoint-restart', 'fingerprint', '"exit_status":78', 'namespace unavailable') }
      expect(File.exist?(File.join(root, 'fingerprint.json'))).to be(false)
    end
  end

  it 'records observed loaded components before an abrupt fixture exit bypasses at_exit' do
    Dir.mktmpdir('pwn-harness-process-') do |root|
      fixture = File.join(root, 'provider.json')
      fingerprint = File.join(root, 'fingerprint.json')
      File.write(fixture, JSON.generate(responses: []))
      env = { 'HOME' => root, 'GEM_HOME' => Gem.dir, 'GEM_PATH' => Gem.path.join(File::PATH_SEPARATOR),
              'PWN_HARNESS_FIXTURE' => fixture, 'PWN_HARNESS_EVENTS' => File.join(root, 'events.jsonl'), 'PWN_HARNESS_FINGERPRINT' => fingerprint }
      command = [RbConfig.ruby, '-I', File.join(HarnessEvaluation::ROOT, 'lib'), '-r',
                 File.join(HarnessEvaluation::ROOT, 'spec/support/harness/fake_provider.rb'), '-e', 'exit!(73)']
      result = HarnessEvaluation.agent_capture(env, command, root, 5)
      expect(result).to include(exit_status: 73, ready_observed: true)
      expect(File.file?(fingerprint)).to be(true), result.inspect
      expect(JSON.parse(File.read(fingerprint)).fetch('components')).not_to be_empty
    end
  end

  it 'loads checkpoint controls across the real namespace exec boundary' do
    Dir.mktmpdir('pwn-harness-process-') do |root|
      fixture = File.join(root, 'provider.json')
      runtime = File.join(root, 'runtime')
      File.write(fixture, JSON.generate(responses: [{ fault: 'crash' }]))
      env = { 'HOME' => root, 'PATH' => HarnessEvaluation.isolated_path, 'GEM_HOME' => Gem.dir, 'GEM_PATH' => Gem.path.join(File::PATH_SEPARATOR),
              'PWN_HARNESS_FIXTURE' => fixture, 'PWN_HARNESS_EVENTS' => File.join(root, 'events.jsonl'),
              'PWN_HARNESS_FINGERPRINT' => File.join(root, 'fingerprint.json'), 'PWN_HARNESS_RUNTIME' => runtime }
      command = [RbConfig.ruby, '-I', File.join(HarnessEvaluation::ROOT, 'lib'), '-r',
                 File.join(HarnessEvaluation::ROOT, 'spec/support/harness/fault_preload.rb'), '-e',
                 'PWN::AI::Agent::MissionNamespace.force_exec = true; load ARGV.shift', File.join(HarnessEvaluation::ROOT, 'bin/pwn-ai'), '--ai', 'Offline checkpoint fixture']
      result = HarnessEvaluation.agent_capture(env, command, root, 10)
      expect(result).to include(exit_status: 73)
      expect(File.file?(File.join(runtime, 'identity.json'))).to be(true), result.inspect
    end
  end

  it 'does not resume a checkpoint that never started after a real child failure' do
    Dir.mktmpdir('pwn-harness-process-') do |root|
      failure = { exit_status: 78, resource_cap: false, ready_observed: false, stdout: '', stderr: 'namespace unavailable' }
      allow(HarnessCLIFaults).to receive(:invoke).and_return(failure)
      report = HarnessCLIFaults.run(output: root)
      expect(HarnessCLIFaults).to have_received(:invoke).exactly(5).times
      expect(report.fetch(:results)).to all(include(outcome: 'FAIL', exit_status: 78))
    end
  end

  it 'redacts child diagnostics before reporting a missing fingerprint' do
    Dir.mktmpdir('pwn-harness-process-') do |root|
      row = { id: 'failed-boot', artifact_root: root, exit_status: 78, stderr: 'password=offline-secret' }
      expect { HarnessPackageAcceptance.validate_fingerprints!([row], '/isolated/gems/pwn') }.to raise_error(RuntimeError) do |error|
        expect(error.message).to include('REDACTED', '78')
        expect(error.message).not_to include('offline-secret')
      end
    end
  end

  it 'requires fresh readiness on restart rather than accepting the previous process marker' do
    Dir.mktmpdir('pwn-harness-process-') do |root|
      File.write(File.join(root, 'harness-ready'), 'previous invocation')
      command = [RbConfig.ruby, '-e', "sleep 0.2; puts 'booted'; STDOUT.flush; File.write(ENV.fetch('PWN_HARNESS_READY'), 'ready'); sleep 60"]
      result = HarnessEvaluation.agent_capture({ 'HOME' => root }, command, root, 0.05)
      expect(result).to include(resource_cap: true, ready_observed: true, stdout: "booted\n", timeout_phase: 'execution')
    end
  end
end
