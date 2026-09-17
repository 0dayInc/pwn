# frozen_string_literal: true

require 'spec_helper'
require 'shellwords'
require 'json'
require 'tmpdir'
require 'fileutils'
require 'base64'

describe 'PWN::AI::Agent::Tools fuzz_campaign' do
  before(:all) do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/fuzz_campaign.rb'
  end

  it 'registers expected tool names' do
    expect(PWN::AI::Agent::Registry.lookup(name: 'fuzz_campaign')).not_to be_nil
  end

  it 'starts AFL with a durable six-hour supervisor and correctly quoted paths' do
    expect(PWN::Plugins::Jobs).to receive(:start).with(hash_including(max_runtime: 21_600, idempotency_key: 'afl-one', session_id: 'session-one')) do |opts|
      argv = Shellwords.split(opts[:command])
      expect(argv.any? { |part| part.include?('PWN::Plugins::AFLplusplus.campaign') }).to eq(true)
      payload = JSON.parse(Base64.decode64(argv.last), symbolize_names: true)
      expect(payload[:in_dir]).to eq('/tmp/input dir')
      expect(payload[:out_dir]).to eq('/tmp/output dir')
      expect(payload[:target]).to include('/tmp/target program')
      { id: '012345abcdef' }
    end
    tool = PWN::AI::Agent::Registry.lookup(name: 'fuzz_campaign')
    expect(tool.handler.call(action: 'start', in_dir: '/tmp/input dir', out_dir: '/tmp/output dir', target: '"/tmp/target program" @@', max_runtime: 21_600, session_id: 'session-one', idempotency_key: 'afl-one')).to include(id: '012345abcdef')
  end

  it 'status auto-triages unique crashes without a second tool call' do
    Dir.mktmpdir('pwn-fuzz-status-') do |dir|
      crashes = File.join(dir, 'crashes')
      FileUtils.mkdir_p(crashes)
      File.binwrite(File.join(crashes, 'id:000000,sig:11'), 'CRASH')
      allow(PWN::Plugins::Jobs).to receive(:status).and_return(id: 'job1', status: 'COMPLETED')
      allow(PWN::Plugins::GDBMI).to receive(:run_to_crash).and_return(signal: 'SIGSEGV', pc: '0x1', fault_addr: '0x1', backtrace: ['main'])
      allow(PWN::Plugins::BinaryParser).to receive(:triage).and_return(file_type: 'elf')
      allow(PWN::Plugins::ExploitDev).to receive(:from_crash).and_return(offset: 8)
      tool = PWN::AI::Agent::Registry.lookup(name: 'fuzz_campaign')
      row = tool.handler.call(action: 'status', id: 'job1', out_dir: dir, target: '/bin/true')
      expect(row[:triage][:unique].length).to eq(1)
      expect(row[:triage][:triaged].first).to include(:crash, :backtrace_hash)
      expect(row[:triage][:pipeline]).to eq('pwn-re-003')
    end
  end

  it 'starts a libFuzzer campaign through the same Jobs supervisor' do
    expect(PWN::Plugins::Jobs).to receive(:start) do |opts|
      payload = JSON.parse(Base64.decode64(Shellwords.split(opts[:command]).last), symbolize_names: true)
      expect(payload[:engine].to_s).to include('libfuzzer')
      { id: 'libf1' }
    end
    tool = PWN::AI::Agent::Registry.lookup(name: 'fuzz_campaign')
    expect(tool.handler.call(action: 'start', engine: 'libfuzzer', in_dir: '/tmp/in', out_dir: '/tmp/out', target: '/tmp/fuzzme')).to include(id: 'libf1')
  end
end
