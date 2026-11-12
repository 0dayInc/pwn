# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Sessions, 'lifecycle audit regressions' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    FileUtils.mkdir_p(File.join(@tmp, '.pwn'))
  end

  def cold_session
    session = described_class.create
    File.utime(Time.at(1), Time.at(1), session[:path])
    session
  end

  it 'pins a cold session with an actual activity lease' do
    session = cold_session
    lease = described_class.activate(session_id: session[:id])
    expect(described_class.protected_session_ids(hot_days: 0)).to include(session[:id])
  ensure
    described_class.deactivate(lease: lease)
  end

  it 'keeps live transcripts and metadata during lean deletion' do
    session = cold_session
    lease = described_class.activate(session_id: session[:id])
    result = described_class.lean!(hot_days: 0, retain_days: 1)
    expect(result[:deleted]).to eq(0)
    expect(File).to exist(session[:path])
    expect(File).to exist(described_class.support_path(kind: :metadata, session_id: session[:id]))
  ensure
    described_class.deactivate(lease: lease)
  end

  it 'does not compact a transcript while an independent live lease is held' do
    session = cold_session
    File.open(session[:path], 'a') { |file| file.puts(JSON.generate(role: 'tool', content: 'fixture ' * 100)) }
    bytes = File.binread(session[:path])
    lease = described_class.activate(session_id: session[:id])
    expect(described_class.send(:compact_transcript!, path: session[:path], tool_max: 10)).to be(false)
    expect(File.binread(session[:path])).to eq(bytes)
    described_class.deactivate(lease: lease)
    expect(described_class.send(:compact_transcript!, path: session[:path], tool_max: 10)).to be(true)
  ensure
    described_class.deactivate(lease: lease)
  end

  it 'previews compaction without creating activity or writer files' do
    session = cold_session
    File.open(session[:path], 'a') { |file| file.puts(JSON.generate(role: 'tool', content: 'fixture ' * 100)) }
    files = Dir.glob(File.join(described_class.sessions_dir, '**', '*'), File::FNM_DOTMATCH)
    expect(described_class.send(:compact_transcript!, path: session[:path], tool_max: 10, dry_run: true)).to be(true)
    expect(Dir.glob(File.join(described_class.sessions_dir, '**', '*'), File::FNM_DOTMATCH)).to eq(files)
  end

  [1, 20, 21, 39, 40, 41].each do |count|
    it "retains disjoint head and tail windows for a #{count}-line transcript" do
      session = cold_session
      rows = Array.new(count) { |index| { 'role' => 'user', 'content' => "fixture #{index}" } }
      File.write(session[:path], rows.map { |row| "#{JSON.generate(row)}\n" }.join)
      File.utime(Time.at(1), Time.at(1), session[:path])
      expect(described_class.retain(days: 1)[:gzipped]).to eq(1)
      actual = Zlib::GzipReader.open("#{session[:path]}.gz") { |gzip| gzip.each_line.map { |line| JSON.parse(line) } }
      expected = count <= 40 ? rows : rows.first(20) + rows.last(20)
      expect(actual).to eq(expected)
    end
  end

  it 'rejects export failure without publishing a success or replacing the previous archive' do
    session = cold_session
    directory = File.join(@tmp, '.pwn', 'exports')
    FileUtils.mkdir_p(directory)
    destination = File.join(directory, "#{session[:id]}.tar.gz")
    File.write(destination, 'previous archive fixture')
    allow(described_class).to receive(:system) do |*_arguments, **options|
      options.fetch(:out).write('incomplete archive')
      false
    end
    expect { described_class.export(session_id: session[:id]) }.to raise_error(IOError, /export|archive|tar/i)
    expect(File.binread(destination)).to eq('previous archive fixture')
    expect(Dir.children(directory)).to eq([File.basename(destination)])
  end

  %i[load export].each do |operation|
    it "rejects traversal before #{operation} can access another store" do
      described_class.sessions_dir
      File.write(File.join(@tmp, 'outside.jsonl'), "#{JSON.generate(role: 'user', content: 'outside fixture')}\n")
      expect { described_class.public_send(operation, session_id: '../outside') }.to raise_error(ArgumentError, /session/i)
    end
  end

  it 'refuses to load a symlinked transcript outside the session store' do
    directory = described_class.sessions_dir
    outside = File.join(@tmp, 'outside.jsonl')
    File.write(outside, "#{JSON.generate(role: 'user', content: 'outside fixture')}\n")
    File.symlink(outside, File.join(directory, 'linked.jsonl'))
    expect { described_class.load(session_id: 'linked') }.to raise_error(IOError, /Unsafe/)
  end

  it 'refuses to export through a symlinked destination directory' do
    session = cold_session
    outside = File.join(@tmp, 'outside-exports')
    Dir.mkdir(outside)
    File.symlink(outside, File.join(@tmp, '.pwn', 'exports'))
    expect { described_class.export(session_id: session[:id]) }.to raise_error(IOError, /Unsafe/)
    expect(Dir.children(outside)).to eq([])
  end

  %i[lean! retain].each do |operation|
    it "rechecks newly published dependencies before #{operation} changes a transcript" do
      session = cold_session
      File.open(session[:path], 'a') { |file| file.puts(JSON.generate(role: 'tool', content: 'fixture ' * 15_000)) }
      cold = Time.now - (20 * 86_400)
      File.utime(cold, cold, session[:path])
      original = File.binread(session[:path])
      published = false
      allow(described_class).to receive(:protected_session_ids).and_wrap_original do |method, opts|
        pins = method.call(opts)
        unless published
          File.write(File.join(@tmp, '.pwn', 'learning.jsonl'), "#{JSON.generate(session_id: session[:id], lesson: 'preserved fixture evidence')}\n")
          published = true
        end
        pins
      end
      result = operation == :lean! ? described_class.lean!(hot_days: 0, retain_days: 30) : described_class.retain(days: 1)
      expect(result[:compacted] || result[:gzipped]).to eq(0)
      expect(File.binread(session[:path])).to eq(original)
    end
  end

  it 'reports unlink failures instead of falsely reporting a deleted session' do
    session = cold_session
    allow(File).to receive(:unlink).and_call_original
    allow(File).to receive(:unlink).with(session[:path]).and_raise(Errno::EACCES)
    expect { described_class.delete(session_id: session[:id], force: true) }.to raise_error(Errno::EACCES)
    expect(File).to exist(session[:path])
  ensure
    allow(File).to receive(:unlink).with(session[:path]).and_call_original if session
  end

  it 'does not overwrite an existing retention archive' do
    session = cold_session
    archive = "#{session[:path]}.gz"
    File.write(archive, 'previous evidence fixture')
    expect(described_class.retain(days: 1)[:records]).to include(hash_including(id: session[:id], state: 'conflict'))
    expect(File.binread(archive)).to eq('previous evidence fixture')
    expect(File).to exist(session[:path])
    expect(Dir.glob("#{session[:path]}.*.tmp")).to eq([])
  end

  it 'retains a session when dependency discovery encounters a symlink archive' do
    session = cold_session
    outside = File.join(@tmp, 'outside-archive')
    File.write(outside, 'previous evidence fixture')
    File.symlink(outside, "#{session[:path]}.gz")
    expect(described_class.retain(days: 1)[:gzipped]).to eq(0)
    expect(File.binread(outside)).to eq('previous evidence fixture')
    expect(File).to exist(session[:path])
  end

  it 'protects a lease acquired after preflight during max-files enforcement' do
    session = cold_session
    File.open(session[:path], 'a') { |file| file.puts(JSON.generate(role: 'user', content: 'substantive fixture conversation ' * 12)) }
    File.utime(Time.at(1), Time.at(1), session[:path])
    lease = nil
    allow(described_class).to receive(:protected_session_ids).and_wrap_original do |original, opts|
      pins = original.call(opts)
      lease ||= described_class.activate(session_id: session[:id])
      pins
    end
    result = described_class.lean!(hot_days: 0, retain_days: 100_000, max_files: 0)
    expect(result[:deleted]).to eq(0)
    expect(File).to exist(session[:path])
  ensure
    described_class.deactivate(lease: lease)
  end

  it 'keeps malformed retention input without publishing a partial archive' do
    session = cold_session
    File.write(session[:path], "not json\n")
    File.utime(Time.at(1), Time.at(1), session[:path])
    # The dependency index already protects malformed evidence, before gzip.
    expect(described_class.retain(days: 1)[:gzipped]).to eq(0)
    expect(File.binread(session[:path])).to eq("not json\n")
    expect(File).not_to exist("#{session[:path]}.gz")
  end

  it 'rechecks a lease acquired after lean preflight before deleting' do
    session = cold_session
    lease = nil
    allow(described_class).to receive(:protected_session_ids).and_wrap_original do |original, opts|
      pins = original.call(opts)
      lease ||= described_class.activate(session_id: session[:id])
      pins
    end
    expect(described_class.lean!(hot_days: 0, retain_days: 1)[:deleted]).to eq(0)
    expect(File).to exist(session[:path])
  ensure
    described_class.deactivate(lease: lease)
  end
end
