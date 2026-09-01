# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe 'REQ-01 through REQ-24 agent surface' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
  end

  {
    'REQ-01' => %w[binary_triage],
    'REQ-02' => %w[pty_open pty_send pty_read pty_close],
    'REQ-03' => %w[job_run job_status job_result],
    'REQ-04' => %w[exploitdev],
    'REQ-05' => %w[fuzz_campaign],
    'REQ-14' => %w[artifacts_list artifacts_get],
    'REQ-15' => %w[finding_record finding_report],
    'REQ-19' => %w[intel_lookup],
    'REQ-20' => %w[session_export],
    'REQ-21' => %w[swarm_map]
  }.each do |req, names|
    it "registers #{req} tools" do
      names.each { |n| expect(PWN::AI::Agent::Registry.lookup(name: n)).not_to be_nil }
    end
  end

  it 'REQ-06 TransparentBrowser.evidence! writes screenshot/dom/har' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      browser = Object.new
      def browser.html
        '<html/>'
      end
      out = PWN::Plugins::TransparentBrowser.evidence!(browser_obj: { browser: browser }, label: 't', session_id: 's')
      expect(File.file?(out[:screenshot])).to be true
      expect(File.file?(out[:dom])).to be true
      expect(File.file?(out[:har])).to be true
    end
  end

  it 'REQ-07 NmapIt.to_findings returns [] for a missing xml file' do
    expect(PWN::Plugins::NmapIt.to_findings(xml_file: '/tmp/no-such-nmap.xml')).to eq([])
  end

  it 'REQ-08 PASS analytical answers are not floored below 0.6' do
    src = File.read('/opt/pwn/lib/pwn/ai/agent/reward.rb')
    expect(src).to include('[score, 0.6].max')
    expect(src).to include('\\bPASS\\b')
  end

  it 'REQ-09 Mistakes.error_class splits auth vs name conflict' do
    expect(PWN::AI::Agent::Mistakes.error_class(error: 'pull access denied')).to eq('auth_denied')
    expect(PWN::AI::Agent::Mistakes.error_class(error: 'name already in use')).to eq('name_conflict')
  end

  it 'REQ-16 compacted tool bodies keep head and path' do
    src = File.read(PWN::AI::Agent::Loop.method(:run).source_location.first)
    expect(src).to include('[compacted path=')
    expect(src).to include('byteslice(0, 2_048)')
  end

  it 'REQ-17 ToolGuard.scope_refusal is a no-op without scope yaml' do
    expect(PWN::AI::Agent::ToolGuard.scope_refusal(command: 'nmap 8.8.8.8')).to be_nil
  end

  it 'REQ-18 Sessions.redact replaces AWS keys' do
    out = PWN::Sessions.redact(content: 'id AKIAIOSFODNN7EXAMPLE extra')
    expect(out).to include('[REDACTED:aws:')
    expect(out).not_to include('AKIAIOSFODNN7EXAMPLE')
  end

  it 'REQ-22 PreflightChecker.route degrades missing bins' do
    row = PWN::Plugins::PreflightChecker.route(name: 'definitely-not-a-bin-zzzz')
    expect(row[:ok]).to be false
    expect(row[:degraded]).to be true
  end

  it 'REQ-24 Sessions.retain reports deleted count' do
    expect(PWN::Sessions.retain(days: 10_000)[:deleted]).to eq(0)
  end
end
