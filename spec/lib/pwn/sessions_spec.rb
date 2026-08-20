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
end
