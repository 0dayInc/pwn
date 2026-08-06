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
    PWN::Memory.clear
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
end
