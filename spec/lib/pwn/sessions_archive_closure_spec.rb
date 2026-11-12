# frozen_string_literal: true

require 'spec_helper'
require 'timeout'

RSpec.describe PWN::Sessions, 'archive lifecycle closure' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    @root = File.join(@tmp, '.pwn')
    FileUtils.mkdir_p(@root)
    stub_const('PWN::Sessions::SESSIONS_DIR', File.join(@root, 'sessions'))
    stub_const('PWN::AI::Agent::Learning::LEARNING_FILE', File.join(@root, 'learning.jsonl'))
  end

  def cold(id)
    session = described_class.create(id: id)
    File.utime(Time.at(1), Time.at(1), session[:path])
    session
  end

  it 'R05 resumes owned archive publication after unlink failure and processes later candidates' do
    first = cold('20000101_000000_00000001')
    bytes = File.binread(first[:path])
    allow(File).to receive(:delete).and_call_original
    allow(File).to receive(:delete).with(first[:path]).and_raise(Errno::EACCES, 'synthetic unlink fault')
    result = described_class.retain(days: 1)
    expect(result[:gzipped]).to eq(0)
    expect(result[:records]).to include(hash_including(id: first[:id], state: 'interrupted'))
    expect(File.binread(first[:path])).to eq(bytes)
    archive = File.binread("#{first[:path]}.gz")
    allow(File).to receive(:delete).with(first[:path]).and_call_original
    second = cold('20000101_000000_00000002')
    retry_result = described_class.retain(days: 1)
    expect(retry_result[:gzipped]).to eq(2)
    expect(File.binread("#{first[:path]}.gz")).to eq(archive)
    expect(File).not_to exist(first[:path])
    expect(File).not_to exist(second[:path])
    expect(File).to exist("#{second[:path]}.gz")
  end

  it 'R05 reports an unowned archive conflict without overwriting it or starving later candidates' do
    first = cold('20000101_000000_00000001')
    second = cold('20000101_000000_00000002')
    File.write("#{first[:path]}.gz", 'foreign evidence')
    result = described_class.retain(days: 1)
    expect(result[:records]).to include(hash_including(id: first[:id], state: 'conflict'))
    expect(result[:gzipped]).to eq(1)
    expect(File.binread("#{first[:path]}.gz")).to eq('foreign evidence')
    expect(File).to exist(first[:path])
    expect(File).not_to exist(second[:path])
  end

  it 'R06 keeps an unowned retention temporary when exclusive creation collides' do
    session = cold('20000101_000000_00000001')
    suffix = 'c' * 24
    path = "#{session[:path]}.#{suffix}.tmp"
    File.write(path, 'foreign temporary')
    allow(SecureRandom).to receive(:hex).and_call_original
    allow(SecureRandom).to receive(:hex).with(12).and_return(suffix)
    begin
      described_class.retain(days: 1)
    rescue Errno::EEXIST
      # Either a checked exception or a per-candidate conflict must preserve ownership.
    end
    expect(File.binread(path)).to eq('foreign temporary')
  end

  it 'R06 keeps an unowned compaction temporary after exclusive-create failure' do
    session = cold('20000101_000000_00000001')
    File.open(session[:path], 'a') { |file| file.puts(JSON.generate(role: 'tool', content: 'fixture ' * 100)) }
    suffix = 'c' * 24
    path = "#{session[:path]}.#{suffix}.tmp"
    File.write(path, 'foreign temporary')
    allow(SecureRandom).to receive(:hex).and_call_original
    allow(SecureRandom).to receive(:hex).with(12).and_return(suffix)
    expect { described_class.send(:compact_transcript!, path: session[:path], tool_max: 10) }.to raise_error(Errno::EEXIST)
    expect(File.binread(path)).to eq('foreign temporary')
  end

  it 'R06 leaves a replacement inode untouched after a tar failure' do
    session = cold('20000101_000000_00000001')
    temporary = nil
    allow(described_class).to receive(:system) do |*_args, **options|
      temporary = options.fetch(:out).path
      File.unlink(temporary)
      File.write(temporary, 'replacement owner')
      false
    end
    expect { described_class.export(session_id: session[:id]) }.to raise_error(IOError, /tar failed/)
    expect(File.binread(temporary)).to eq('replacement owner')
  end

  it 'R06 does not block or remove an owned temporary reacquired by another active holder' do
    session = cold('20000101_000000_00000001')
    held = nil
    temporary = nil
    allow(described_class).to receive(:system).and_return(false)
    allow(described_class).to receive(:remove_owned_temporary).and_wrap_original do |method, options|
      temporary = options[:path]
      held = File.open(temporary, File::RDWR) # rubocop:disable Style/FileOpen -- independently held until example ensure
      held.flock(File::LOCK_EX)
      method.call(options)
    end
    expect { Timeout.timeout(3) { described_class.export(session_id: session[:id]) } }.to raise_error(IOError, /tar failed/)
    expect(File).to exist(temporary)
  ensure
    held&.close
  end

  it 'R06 reserves the export temporary before invoking tar and preserves a collision' do
    session = cold('20000101_000000_00000001')
    directory = File.join(@root, 'exports')
    FileUtils.mkdir_p(directory)
    suffix = 'c' * 24
    path = File.join(directory, ".#{session[:id]}.#{suffix}.tmp")
    File.write(path, 'foreign temporary')
    allow(SecureRandom).to receive(:hex).and_call_original
    allow(SecureRandom).to receive(:hex).with(12).and_return(suffix)
    allow(described_class).to receive(:system).and_return(false)
    expect { described_class.export(session_id: session[:id]) }.to raise_error(Errno::EEXIST)
    expect(described_class).not_to have_received(:system)
    expect(File.binread(path)).to eq('foreign temporary')
  end
end
