# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe PWN::Sessions do
  it 'should display information for authors' do
    authors_response = PWN::Sessions
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Sessions
    expect(help_response).to respond_to :help
  end

  it 'should support create/list/append/load/delete' do
    s = PWN::Sessions.create(title: 'spec test session')
    expect(s[:id]).not_to be_nil
    PWN::Sessions.append(session_id: s[:id], role: 'user', content: 'test input')
    t = PWN::Sessions.load(session_id: s[:id])
    expect(t.size).to be >= 2
    # Hot sessions are pinned — force required for intentional delete.
    expect { PWN::Sessions.delete(session_id: s[:id]) }.to raise_error(/protected/)
    PWN::Sessions.delete(session_id: s[:id], force: true)
    expect(PWN::Sessions.list.any? { |x| x[:id] == s[:id] }).to be false
  end

  it 'caps tool/assistant content on append per TOOL_CONTENT_MAX/ASSISTANT_CONTENT_MAX' do
    s = PWN::Sessions.create(title: 'cap test')
    tool_big = 'T' * (PWN::Sessions::TOOL_CONTENT_MAX + 100)
    asst_big = 'A' * (PWN::Sessions::ASSISTANT_CONTENT_MAX + 100)
    PWN::Sessions.append(session_id: s[:id], role: 'tool', content: tool_big)
    PWN::Sessions.append(session_id: s[:id], role: 'assistant', content: asst_big)
    rows = PWN::Sessions.load(session_id: s[:id])
    tool = rows.find { |e| e[:role] == 'tool' }
    asst = rows.find { |e| e[:role] == 'assistant' }
    expect(tool[:content].bytesize).to be <= (PWN::Sessions::TOOL_CONTENT_MAX + 20)
    expect(asst[:content].bytesize).to be <= (PWN::Sessions::ASSISTANT_CONTENT_MAX + 20)
    expect(tool[:content]).to include('[compacted]')
  ensure
    PWN::Sessions.delete(session_id: s[:id], force: true) if s
  end

  it 'lean! respects MIN_STUB_BYTES and HOT_DAYS pins' do
    tmp = Dir.mktmpdir
    stub_const('PWN::Sessions::SESSIONS_DIR', tmp)
    hot = PWN::Sessions.create(title: 'hot')
    PWN::Sessions.append(session_id: hot[:id], role: 'user', content: 'substantive user line here')
    # cold stub: tiny file outside hot window
    stub_id = '19990101_000000_deadbeef'
    stub_path = File.join(tmp, "#{stub_id}.jsonl")
    File.write(stub_path, %({"role":"system","content":"Session started","timestamp":"1999-01-01T00:00:00Z"}
))
    File.utime(Time.at(0), Time.at(0), stub_path)
    res = PWN::Sessions.lean!(current_session_id: hot[:id])
    expect(File.exist?(File.join(tmp, "#{hot[:id]}.jsonl"))).to be true
    expect(File.exist?(stub_path)).to be false
    expect(res[:deleted]).to be >= 1
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'recall searches prior session transcripts and skips the current session' do
    tmp = Dir.mktmpdir
    stub_const('PWN::Sessions::SESSIONS_DIR', tmp)
    old = PWN::Sessions.create(id: '20200101_000000_oldone', title: 'old')
    PWN::Sessions.append(session_id: old[:id], role: 'user', content: 'use hping3 for a ping sweep')
    PWN::Sessions.append(session_id: old[:id], role: 'assistant', content: 'Prefer pwn_eval then shell for that')
    cur = PWN::Sessions.create(id: '20260101_000000_curone', title: 'current')
    PWN::Sessions.append(session_id: cur[:id], role: 'user', content: 'unrelated current chatter')
    hits = PWN::Sessions.recall(query: 'hping3', exclude_session_id: cur[:id], limit: 8)
    expect(hits).to be_an(Array)
    expect(hits).not_to be_empty
    expect(hits.all? { |h| h[:session_id] != cur[:id] }).to eq true
    expect(hits.any? { |h| h[:content].to_s.include?('hping3') }).to eq true
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'previous_id returns the newest session that is not the current one' do
    tmp = Dir.mktmpdir
    stub_const('PWN::Sessions::SESSIONS_DIR', tmp)
    old = PWN::Sessions.create(id: '20200101_000000_oldses', title: 'old')
    PWN::Sessions.append(session_id: old[:id], role: 'user', content: 'SHIP MARKER LAST SESSION')
    cur = PWN::Sessions.create(id: '20260101_000000_curses', title: 'current')
    PWN::Sessions.append(session_id: cur[:id], role: 'user', content: 'what did I just say?')
    expect(PWN::Sessions.previous_id(exclude_session_id: cur[:id])).to eq(old[:id])
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'to_llm_messages returns this session user/assistant turns for the next LLM call' do
    tmp = Dir.mktmpdir
    stub_const('PWN::Sessions::SESSIONS_DIR', tmp)
    sid = 'llm_hist_sess'
    PWN::Sessions.create(id: sid, title: 'hist')
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'where is OpenGoal?')
    PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'in open_goal.rb')
    PWN::Sessions.append(session_id: sid, role: 'tool', content: 'ignore me')
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'and Loop.run?')
    PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'in loop.rb around resume?')
    msgs = PWN::Sessions.to_llm_messages(session_id: sid)
    expect(msgs.map { |m| m[:role] }).to eq(%w[user assistant user assistant])
    expect(msgs.map { |m| m[:content] }).to include('where is OpenGoal?', 'in open_goal.rb', 'and Loop.run?', 'in loop.rb around resume?')
    expect(msgs.none? { |m| m[:content].to_s.include?('ignore me') }).to eq true
    skip_last = PWN::Sessions.to_llm_messages(session_id: sid, skip_request: 'and Loop.run?')
    expect(skip_last.last[:content]).to eq('in loop.rb around resume?')
    expect(skip_last.none? { |m| m[:content] == 'and Loop.run?' && m[:role] == 'user' }).to eq true
    tiny = PWN::Sessions.to_llm_messages(session_id: sid, max_chars: 40)
    expect(tiny.last[:content]).to include('loop.rb')
    expect(tiny.map { |m| m[:content].to_s.length }.sum).to be <= 80
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'retrieves a throttle-evasion session from a rate-limit paraphrase' do
    Dir.mktmpdir do |dir|
      allow(described_class).to receive(:sessions_dir).and_return(dir)
      FileUtils.mkdir_p(dir)
      sid = described_class.create(id: 'throttle_fix', title: 'login')[:id]
      described_class.append(session_id: sid, role: 'assistant', content: 'throttle evasion on the login form')
      hits = described_class.recall(query: 'how did I bypass the login rate limit')
      expect(hits.map { |h| h[:session_id] }).to include(sid)
    end
  end

  it 'redacts AWS access-key shaped tokens' do
    out = described_class.redact(content: 'id AKIAIOSFODNN7EXAMPLE extra')
    expect(out).to include('[REDACTED:aws:')
    expect(out).not_to include('AKIAIOSFODNN7EXAMPLE')
  end

  it 'gzips old transcripts and leaves findings alone' do
    Dir.mktmpdir do |dir|
      allow(described_class).to receive(:sessions_dir).and_return(File.join(dir, 'sessions'))
      FileUtils.mkdir_p(described_class.sessions_dir)
      path = File.join(described_class.sessions_dir, 'old.jsonl')
      File.write(path, %({"role":"user","content":"hi"}\n))
      File.utime(Time.now - (10 * 86_400), Time.now - (10 * 86_400), path)
      findings = File.join(dir, 'findings.jsonl')
      File.write(findings, 'keep')
      stub_const('PWN::Plugins::Findings::FILE', findings)
      r = described_class.retain(days: 1)
      expect(r[:gzipped].to_i).to be >= 1
      expect(File.file?(path)).to be false
      expect(File.file?("#{path}.gz")).to be true
      expect(File.read(findings)).to eq('keep')
    end
  end

  it 'retain with a huge keep window reports zero deleted' do
    expect(described_class.retain(days: 10_000)[:deleted]).to eq(0)
  end

  it 'export writes a sha256 manifest next to the tarball' do
    Dir.mktmpdir do |dir|
      allow(described_class).to receive(:sessions_dir).and_return(File.join(dir, 'sessions'))
      FileUtils.mkdir_p(described_class.sessions_dir)
      allow(Dir).to receive(:home).and_return(dir)
      sid = 'exportme'
      File.write(File.join(described_class.sessions_dir, "#{sid}.jsonl"), %({"role":"user"}\n))
      out = described_class.export(session_id: sid)
      expect(File.file?(out[:path])).to be true
      expect(out[:manifest]).to be_a(Hash)
      expect(out[:manifest].values.first.to_s).to match(/\A[0-9a-f]{64}\z/)
    end
  end
end
