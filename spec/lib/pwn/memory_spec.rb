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
