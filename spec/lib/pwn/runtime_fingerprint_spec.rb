# frozen_string_literal: true

require 'spec_helper'
require 'open3'
require 'tmpdir'
require 'pry'
require 'stringio'

RSpec.describe PWN::RuntimeFingerprint do
  it 'reports unknown pre-observer bytes without claiming all code is current' do
    report = described_class.report
    expect(report[:components]).not_to be_empty
    expect(report[:components].find { |row| row[:path].end_with?('/pwn.rb') }[:state]).to eq('unknown_loaded_digest')
    expect(report[:loaded_version]).to eq(PWN::VERSION)
    expect(report[:process_start]).to have_key(:source)
  end

  it 'detects an edited loaded component and does not silently update its baseline' do
    Dir.mktmpdir do |root|
      FileUtils.mkdir_p(File.join(root, 'pwn'))
      FileUtils.cp(File.expand_path('../../../lib/pwn/runtime_fingerprint.rb', __dir__), File.join(root, 'pwn/runtime_fingerprint.rb'))
      source = File.join(root, 'pwn/component.rb')
      File.write(source, "PWN.const_set(:Fixture, :old)\n")
      code = "require 'json'; require 'pwn/runtime_fingerprint'; require 'pwn/component'; File.write(ARGV[0], 'PWN.const_set(:Fixture, :new)'); puts JSON.generate(PWN::RuntimeFingerprint.report)"
      stdout, stderr, status = Open3.capture3({ 'HOME' => root }, RbConfig.ruby, '-I', root, '-e', code, source, unsetenv_others: true)
      expect(status.success?).to be(true), stderr
      row = JSON.parse(stdout)
      expect(row['restart_required']).to be(true), row.inspect
      expect(row['components'].find { |item| item['path'] == source }['state']).to eq('changed_since_compile_observation')
    end
  end

  it 'reports an expected deployment-root mismatch' do
    expect(described_class.report(expected_root: '/not-this-install')[:root_mismatch]).to be(true)
  end

  context 'existing status surface' do
    include_context 'pwn tmp sandbox'

    it 'prints real read-only deployment diagnostics without starting model work' do
      allow(Dir).to receive(:home).and_return(@tmp)
      stub_const('PWN::AI::Agent::SkillReview::LEDGER', File.join(@tmp, 'skill_review.jsonl'))
      stub_const('PWN::AI::Agent::OpenGoal::GOAL_FILE', File.join(@tmp, 'open_goal.json'))
      allow(Pry).to receive(:history).and_return(Pry::History.new(file_path: File.join(@tmp, 'history')))
      console = PWN::Plugins::REPL::AIConsole::Console.new(pry: Pry.new, input: StringIO.new, curses: nil, getch: nil)
      expect(PWN::AI::Agent::Loop).not_to receive(:run)
      expect(console).to receive(:add).with(:info, include('pwn-runtime-fingerprint-v1', 'loaded_version', 'unknown_loaded_digest')).and_call_original
      console.submit('/status')
    ensure
      console&.send(:stop_worker)
    end
  end
end
