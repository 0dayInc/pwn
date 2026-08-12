# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe PWN::Memory do
  it 'should display information for authors' do
    authors_response = PWN::Memory
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Memory
    expect(help_response).to respond_to :help
  end

  it 'should support remember/recall/forget/clear' do
    tmp = Dir.mktmpdir
    stub_const('PWN::Memory::MEMORY_FILE', File.join(tmp, 'memory.json'))
    PWN::Memory.clear(force: true)
    PWN::Memory.remember(key: :test_fact, value: 'pwn-ai test memory', category: :fact)
    res = PWN::Memory.recall(query: 'test')
    expect(res.keys).to include(:test_fact)
    PWN::Memory.forget(key: :test_fact)
    expect(PWN::Memory.recall(query: 'test').keys).to be_empty
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'refuses empty overwrite of a non-empty memory.json without force' do
    tmp = Dir.mktmpdir
    path = File.join(tmp, 'memory.json')
    stub_const('PWN::Memory::MEMORY_FILE', path)
    PWN::Memory.remember(key: :keep_me, value: 'important', category: :lesson)
    before = File.read(path)
    res = PWN::Memory.save(mem: {})
    expect(File.read(path)).to eq(before)
    expect(res.keys).to include(:keep_me)
    PWN::Memory.save(mem: {}, force: true)
    expect(File.read(path).strip).to eq('{}')
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'enforces VALUE_MAX_CHARS on remember' do
    tmp = Dir.mktmpdir
    stub_const('PWN::Memory::MEMORY_FILE', File.join(tmp, 'memory.json'))
    PWN::Memory.clear(force: true)
    long = 'x' * (PWN::Memory::VALUE_MAX_CHARS + 50)
    PWN::Memory.remember(key: :long_val, value: long, category: :fact)
    v = PWN::Memory.load[:long_val][:value]
    expect(v.bytesize).to be <= (PWN::Memory::VALUE_MAX_CHARS + 20)
    expect(v).to include('[compacted]')
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'refuses forget/clear on protected keys without force' do
    tmp = Dir.mktmpdir
    stub_const('PWN::Memory::MEMORY_FILE', File.join(tmp, 'memory.json'))
    PWN::Memory.clear(force: true)
    PWN::Memory.remember(key: :operator_pref_test, value: 'keep', category: :preference)
    PWN::Memory.remember(key: :process_sop_test, value: 'keep', category: :lesson)
    expect { PWN::Memory.forget(key: :operator_pref_test) }.to raise_error(/protected/)
    expect { PWN::Memory.forget(key: :process_sop_test) }.to raise_error(/protected/)
    expect { PWN::Memory.clear }.to raise_error(/force:true/)
    expect(PWN::Memory.forget(key: :operator_pref_test, force: true)).to be true
    expect(PWN::Memory.load.keys).not_to include(:operator_pref_test)
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end

  it 'recall begins at previous assistant response and walks backward in-session' do
    mem_tmp = Dir.mktmpdir('pwn-mem')
    sess_tmp = Dir.mktmpdir('pwn-sess')
    stub_const('PWN::Memory::MEMORY_FILE', File.join(mem_tmp, 'memory.json'))
    stub_const('PWN::Sessions::SESSIONS_DIR', sess_tmp)
    PWN::Memory.clear(force: true)

    # Durable entry (should trail session turns when room remains).
    PWN::Memory.remember(key: :durable_fact, value: 'persistent knowledge', category: :fact)

    sess = PWN::Sessions.create(title: 'recall-order-test')
    sid = sess[:id]
    # Empty / invalid should be skipped.
    PWN::Sessions.append(session_id: sid, role: 'user', content: '')
    PWN::Sessions.append(session_id: sid, role: 'user', content: '   ')
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'first user question')
    PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'first assistant answer')
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'second user question')
    PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'second assistant answer PREVIOUS')
    # Current user turn after previous response — not older than previous, so excluded.
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'third current user')
    PWN::Sessions.append(session_id: sid, role: 'assistant', content: '') # empty invalid

    turns = PWN::Memory.session_turns(session_id: sid, limit: 20)
    expect(turns.first[:value]).to eq('second assistant answer PREVIOUS')
    expect(turns.first[:role]).to eq('assistant')
    expect(turns.first[:source]).to eq('session_backward')
    values = turns.map { |t| t[:value] }
    expect(values).to eq(
      [
        'second assistant answer PREVIOUS',
        'second user question',
        'first assistant answer',
        'first user question'
      ]
    )
    expect(values).not_to include('third current user')
    expect(values).not_to include('')

    res = PWN::Memory.recall(session_id: sid, limit: 10)
    keys = res.keys
    expect(keys.first.to_s).to match(/session_turn_#{sid}_/)
    expect(res[keys.first][:value]).to eq('second assistant answer PREVIOUS')
    # durable fills after session
    expect(keys).to include(:durable_fact)

    # category: :session → session only
    only_sess = PWN::Memory.recall(session_id: sid, category: :session, limit: 10)
    expect(only_sess.keys).not_to include(:durable_fact)
    expect(only_sess.values.map { |v| v[:value] }.first).to eq('second assistant answer PREVIOUS')

    # include_session:false keeps durable-only path for to_context
    durable_only = PWN::Memory.recall(session_id: sid, include_session: false, limit: 10)
    expect(durable_only.keys).to eq([:durable_fact])

    ctx = PWN::Memory.to_context(limit: 5)
    expect(ctx).to include('durable_fact')
    expect(ctx).not_to include('second assistant answer PREVIOUS')
  ensure
    FileUtils.rm_rf(mem_tmp) if mem_tmp
    FileUtils.rm_rf(sess_tmp) if sess_tmp
  end

  it 'recent_dialog returns chronological prior user/assistant pairs' do
    mem_tmp = Dir.mktmpdir('pwn-mem')
    sess_tmp = Dir.mktmpdir('pwn-sess')
    stub_const('PWN::Memory::MEMORY_FILE', File.join(mem_tmp, 'memory.json'))
    stub_const('PWN::Sessions::SESSIONS_DIR', sess_tmp)
    PWN::Memory.clear(force: true)
    sid = 'dialog_spec'
    PWN::Sessions.create(id: sid, title: 'dialog-spec')
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'first user')
    PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'first asst')
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'THIS WAS MY LAST REQUEST')
    PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'second asst')

    dialog = PWN::Memory.recent_dialog(session_id: sid, pairs: 1)
    expect(dialog.map { |d| d[:role] }).to eq(%w[user assistant])
    expect(dialog[0][:content]).to eq('THIS WAS MY LAST REQUEST')
    expect(dialog[1][:content]).to eq('second asst')

    expect(PWN::Memory.prior_user_message(session_id: sid)[:content]).to eq('THIS WAS MY LAST REQUEST')
    expect(PWN::Memory.prior_assistant_message(session_id: sid)[:content]).to eq('second asst')
  ensure
    FileUtils.rm_rf(mem_tmp) if mem_tmp
    FileUtils.rm_rf(sess_tmp) if sess_tmp
  end

  it 'find_turn_pair matches a quoted earlier utterance and skips meta recall pairs' do
    mem_tmp = Dir.mktmpdir('pwn-mem')
    sess_tmp = Dir.mktmpdir('pwn-sess')
    stub_const('PWN::Memory::MEMORY_FILE', File.join(mem_tmp, 'memory.json'))
    stub_const('PWN::Sessions::SESSIONS_DIR', sess_tmp)
    PWN::Memory.clear(force: true)
    sid = 'pair_spec'
    PWN::Sessions.create(id: sid, title: 'pair-spec')
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'howdy ho from down below!')
    PWN::Sessions.append(session_id: sid, role: 'assistant', content: 'Howdy ho right back! System is up.')
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'what did I just say?')
    PWN::Sessions.append(session_id: sid, role: 'assistant', content: "You just said:\n\nhowdy ho from down below!")
    PWN::Sessions.append(session_id: sid, role: 'user', content: 'and what did you say when I said that?')
    PWN::Sessions.append(
      session_id: sid,
      role: 'assistant',
      content: "Immediately prior user message:\nwhat did I just say?\n\nImmediately prior assistant response:\nYou just said:\n\nhowdy ho from down below!"
    )

    pairs = PWN::Memory.turn_pairs(session_id: sid, pairs: 6)
    expect(pairs.length).to eq(3)

    hit = PWN::Memory.find_turn_pair(session_id: sid, match: 'howdy ho from down below!')
    expect(hit).not_to be_nil
    expect(hit[:user_content]).to eq('howdy ho from down below!')
    expect(hit[:assistant_content]).to include('Howdy ho right back')

    non_meta = PWN::Memory.find_turn_pair(session_id: sid, skip_meta: true)
    expect(non_meta[:user_content]).to eq('howdy ho from down below!')
    expect(non_meta[:assistant_content]).to include('Howdy ho right back')

    expect(PWN::Memory.prior_assistant_message(session_id: sid, skip_meta: true)[:content]).to include('Howdy ho right back')
  ensure
    FileUtils.rm_rf(mem_tmp) if mem_tmp
    FileUtils.rm_rf(sess_tmp) if sess_tmp
  end

  it 'lean! drops expired session_* but keeps protected prefixes' do
    tmp = Dir.mktmpdir
    stub_const('PWN::Memory::MEMORY_FILE', File.join(tmp, 'memory.json'))
    PWN::Memory.clear(force: true)
    PWN::Memory.remember(key: :operator_pref_x, value: 'pref', category: :preference)
    PWN::Memory.remember(key: :session_old, value: 'ephemeral', category: :fact)
    mem = PWN::Memory.load
    mem[:session_old][:timestamp] = (Time.now.utc - (PWN::Memory::EPHEMERAL_TTL_SECS + 100)).iso8601
    PWN::Memory.save(mem: mem)
    res = PWN::Memory.lean!
    expect(res[:removed]).to be >= 1
    expect(PWN::Memory.load.keys).to include(:operator_pref_x)
    expect(PWN::Memory.load.keys).not_to include(:session_old)
  ensure
    FileUtils.rm_rf(tmp) if tmp
  end
end
