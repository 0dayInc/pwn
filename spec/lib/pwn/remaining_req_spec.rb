# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'zlib'
require 'fileutils'
require 'json'

describe 'remaining DEBUG-2026-09-01 REQ surface' do
  describe 'REQ-10 lesson quarantine' do
    it 'tags candidates UNVERIFIED, promotes after two successes, demotes after two contradictions' do
      Dir.mktmpdir do |dir|
        stub_const('PWN::AI::Agent::Learning::LESSONS_FILE', File.join(dir, 'lessons.json'))
        row = PWN::AI::Agent::Learning.lesson_record(text: 'always ls parent first')
        expect(PWN::AI::Agent::Learning.lesson_prompt).to include('[UNVERIFIED]')
        PWN::AI::Agent::Learning.lesson_observe(id: row[:id], success: true)
        PWN::AI::Agent::Learning.lesson_observe(id: row[:id], success: true)
        expect(PWN::AI::Agent::Learning.lesson_prompt).not_to include('[UNVERIFIED]')
        expect(PWN::AI::Agent::Learning.lesson_prompt).to include('always ls parent first')
        PWN::AI::Agent::Learning.lesson_observe(id: row[:id], success: false)
        PWN::AI::Agent::Learning.lesson_observe(id: row[:id], success: false)
        expect(PWN::AI::Agent::Learning.lesson_prompt).not_to include('always ls parent first')
      end
    end
  end

  describe 'REQ-11 hybrid session recall' do
    it 'retrieves a throttle-evasion session from a rate-limit paraphrase' do
      Dir.mktmpdir do |dir|
        allow(PWN::Sessions).to receive(:sessions_dir).and_return(dir)
        FileUtils.mkdir_p(dir)
        sid = PWN::Sessions.create(id: 'throttle_fix', title: 'login')[:id]
        PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'throttle evasion on the login form')
        hits = PWN::Sessions.recall(query: 'how did I bypass the login rate limit')
        expect(hits.map { |h| h[:session_id] }).to include(sid)
      end
    end
  end

  describe 'REQ-12 runtime p95' do
    it 'predicts timeout from recorded runtimes and flags auto-job over 120s' do
      Dir.mktmpdir do |dir|
        stub_const('PWN::AI::Agent::ToolGuard::RUNTIMES_FILE', File.join(dir, 'runtimes.json'))
        10.times { PWN::AI::Agent::ToolGuard.record_runtime(command_class: 'nmap', seconds: 100) }
        pred = PWN::AI::Agent::ToolGuard.predicted_timeout(command_class: 'nmap')
        expect(pred).to be_within(pred * 0.2).of(150)
        expect(PWN::AI::Agent::ToolGuard.auto_job?(command_class: 'nmap', predicted: 180)).to be true
        expect(PWN::AI::Agent::ToolGuard.auto_job?(command_class: 'ls', predicted: 8)).to be false
      end
    end
  end

  describe 'REQ-05 fuzzer_stats' do
    it 'parses execs_per_sec from an AFL fuzzer_stats file' do
      Dir.mktmpdir do |dir|
        File.write(File.join(dir, 'fuzzer_stats'), "execs_per_sec        : 1234.5\npaths_total          : 9\nunique_crashes       : 2\n")
        stats = PWN::Plugins::AFLplusplus.parse_stats(out_dir: dir)
        expect(stats[:execs_per_sec] || stats['execs_per_sec']).to eq('1234.5')
      end
    end
  end

  describe 'REQ-15 finding PoC validation' do
    it 'rejects findings without poc artifacts and renders reports with them' do
      Dir.mktmpdir do |dir|
        stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
        expect { PWN::Plugins::Findings.record(title: 'xss') }.to raise_error(/poc/i)
        poc = File.join(dir, 'poc.rb')
        File.write(poc, 'puts 1')
        row = PWN::Plugins::Findings.record(title: 'xss', poc_artifacts: [poc], severity: 'high')
        expect(row[:poc_artifacts]).to include(poc)
        out = PWN::Plugins::Findings.render(dir_path: dir, report_name: 'findings')
        expect(File.file?(out[:markdown])).to be true
        expect(File.file?(out[:html])).to be true
        expect(File.file?(out[:json])).to be true
      end
    end
  end

  describe 'REQ-19 offline intel' do
    it 'returns log4shell for CVE-2021-44228 without searchsploit' do
      allow(PWN::Plugins::PreflightChecker).to receive(:bin?).and_return(false)
      row = PWN::Plugins::ExploitDB.search(query: 'CVE-2021-44228')
      blob = row.to_s.downcase
      expect(blob).to match(/log4|44228/)
    end
  end

  describe 'REQ-21 swarm_map parallel' do
    it 'maps several ports and returns a merged result set' do
      rows = PWN::AI::Agent::Swarm.map_targets(targets: '127.0.0.1', ports: '1,9,22,80')
      expect(rows.length).to eq(4)
      expect(rows.map { |r| r[:port] }.uniq.length).to eq(4)
    end
  end

  describe 'REQ-22 capability pick' do
    it 'selects the first healthy alternative for a proxy task' do
      allow(PWN::Plugins::PreflightChecker).to receive(:bin?).and_call_original
      allow(PWN::Plugins::PreflightChecker).to receive(:bin?).with(name: 'burpsuite').and_return(false)
      allow(PWN::Plugins::PreflightChecker).to receive(:bin?).with(name: 'zaproxy').and_return(true)
      row = PWN::Plugins::PreflightChecker.pick(task: 'proxy')
      expect(row[:ok]).to be true
      expect(row[:name]).to eq('zaproxy')
    end
  end

  describe 'REQ-24 gzip retain' do
    it 'gzips old transcripts and leaves findings alone' do
      Dir.mktmpdir do |dir|
        allow(PWN::Sessions).to receive(:sessions_dir).and_return(File.join(dir, 'sessions'))
        FileUtils.mkdir_p(PWN::Sessions.sessions_dir)
        path = File.join(PWN::Sessions.sessions_dir, 'old.jsonl')
        File.write(path, "{\"role\":\"user\",\"content\":\"hi\"}\n")
        File.utime(Time.now - (10 * 86_400), Time.now - (10 * 86_400), path)
        findings = File.join(dir, 'findings.jsonl')
        File.write(findings, 'keep')
        stub_const('PWN::Plugins::Findings::FILE', findings)
        r = PWN::Sessions.retain(days: 1)
        expect(r[:gzipped].to_i).to be >= 1
        expect(File.file?(path)).to be false
        expect(File.file?("#{path}.gz")).to be true
        expect(File.read(findings)).to eq('keep')
      end
    end
  end

  describe 'REQ-20 export manifest' do
    it 'writes a sha256 manifest next to the tarball' do
      Dir.mktmpdir do |dir|
        allow(PWN::Sessions).to receive(:sessions_dir).and_return(File.join(dir, 'sessions'))
        FileUtils.mkdir_p(PWN::Sessions.sessions_dir)
        allow(Dir).to receive(:home).and_return(dir)
        sid = 'exportme'
        File.write(File.join(PWN::Sessions.sessions_dir, "#{sid}.jsonl"), "{\"role\":\"user\"}\n")
        out = PWN::Sessions.export(session_id: sid)
        expect(File.file?(out[:path])).to be true
        expect(out[:manifest]).to be_a(Hash)
        expect(out[:manifest].values.first.to_s).to match(/\A[0-9a-f]{64}\z/)
      end
    end
  end
end
