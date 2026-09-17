# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::ArtifactRegistry do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  describe 'spill' do
    before do
      @artifact_dir = Dir.mktmpdir
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(@artifact_dir, 'artifacts'))
    end

    after do
      FileUtils.remove_entry(@artifact_dir)
    end

    it 'stores exact bytes privately under a session and short digest' do
      bytes = "\x00\xffhello".b
      stored = described_class.spill(bytes: bytes, session_id: 'session-1')
      expect(stored).to include(handle: "session-1/#{Digest::SHA256.hexdigest(bytes)[0, 8]}.bin", bytes: bytes.bytesize, sha256: Digest::SHA256.hexdigest(bytes))
      expect(File.binread(stored[:path])).to eq(bytes)
      expect(File.stat(stored[:path]).mode & 0o777).to eq(0o600)
      expect(File.stat(File.dirname(stored[:path])).mode & 0o777).to eq(0o700)
      expect(File.stat(described_class::ROOT).mode & 0o777).to eq(0o700)
      expect(described_class.spill(bytes: bytes, session_id: 'session-1')).to eq(stored)
    end

    it 'pages 50 MiB losslessly with bounded reads and a streaming digest' do
      bytes = (0..255).to_a.pack('C*') * (50 * 1024 * 1024 / 256)
      stored = described_class.spill(bytes: bytes, session_id: 'large')
      expected = Digest::SHA256.hexdigest(bytes)
      digest = Digest::SHA256.new
      offset = 0
      pages = 0
      loop do
        page = described_class.read_page(handle: stored[:handle], offset: offset, length: 1_000_000)
        expect(page[:bytes]).to be <= 2048
        expect(page).to include(handle: stored[:handle], total_bytes: bytes.bytesize, encoding: 'base64', mode: 'base64')
        decoded = Base64.strict_decode64(page[:body])
        digest.update(decoded)
        offset = page[:next_offset]
        pages += 1
        break if page[:eof]
      end
      expect(offset).to eq(bytes.bytesize)
      expect(digest.hexdigest).to eq(expected)
      puts "artifact paging verified: bytes=#{offset} pages=#{pages} sha256=#{digest.hexdigest}"
    end

    it 'preserves split UTF-8 bytes, explicit encodings, refs and EOF metadata' do
      stored = described_class.spill(bytes: 'éabc', session_id: 'text')
      first = described_class.read_page(handle: stored[:handle], length: 1)
      expect(Base64.strict_decode64(first[:body])).to eq("\xc3".b)
      expect(described_class.read_page(ref: stored[:path], offset: 2, length: 99, max_length: 2)).to include(body: 'ab', bytes: 2, eof: false, next_offset: 4)
      expect(described_class.read_page(path: stored[:path], mode: 'hex', length: 2)).to include(hex: 'c3a9', body: 'c3a9')
      expect(described_class.read_page(path: stored[:path], mode: 'base64', offset: 99)).to include(body: '', bytes: 0, eof: true, next_offset: 99)
      expect { described_class.read_page(handle: '../text/12345678.bin') }.to raise_error(ArgumentError)
      expect { described_class.read_page(path: stored[:path], offset: -1) }.to raise_error(ArgumentError)
      expect { described_class.read_page(path: stored[:path], sha256: 'bad') }.to raise_error(/sha256 mismatch/)
    end

    it 'bounds get reads rather than loading the entire file' do
      stored = described_class.spill(bytes: 'x' * 100_000, session_id: 'get')
      expect(File).to receive(:binread).with(stored[:path], 65_536).and_call_original
      expect(described_class.get(path: stored[:path])[:body].bytesize).to eq(65_536)
    end

    it 'greps complete lines across page boundaries with bounded previews and resumable byte offsets' do
      bytes = "first\n#{'x' * 2046}BOUNDARY#{'y' * 2_100_000}\nlast\xff\n".b
      stored = described_class.spill(bytes: bytes, session_id: 'grep')
      first = described_class.grep(handle: stored[:handle], regex: 'x', limit: 1)
      expect(first[:matches].first).to include(offset: 6, fragment_offset: 6, bytes: 2048, continued: true)
      expect(first).to include(next_offset: bytes.index('last'), eof: false, semantics: 'binary_lines')
      offsets = []
      cursor = 0
      loop do
        result = described_class.grep(handle: stored[:handle], regex: 'last', offset: cursor)

        offsets.concat(result[:matches].map { |match| match[:offset] })
        expect(result[:next_offset]).to be > cursor
        cursor = result[:next_offset]
        break if result[:eof]
      end
      expect(offsets).to eq([bytes.index('last')])
      boundary = described_class.grep(handle: stored[:handle], regex: 'BOUNDARY')
      expect(boundary[:matches].first[:offset]).to eq(bytes.index('BOUNDARY'))
      bounded = described_class.grep(handle: stored[:handle], regex: 'BOUNDARY', max_bytes: 32)
      expect(bounded[:matches].first[:text]).to include('BOUNDARY')
      expect(bounded[:matches].sum { |hit| hit[:bytes] }).to be <= 32
      last = described_class.grep(path: stored[:path], regex: 'last', offset: bytes.index('last'))
      expect(Base64.strict_decode64(last[:matches].first[:text])).to eq("last\xff\n".b)
    end

    it 'caps grep match counts and regex runtime and rejects invalid regexes' do
      stored = described_class.spill(bytes: "hit\n" * 100, session_id: 'grep-limit')
      allow(Regexp).to receive(:new).and_call_original
      expect(Regexp).to receive(:new).with('hit'.b, Regexp::NOENCODING, timeout: 0.05).and_call_original
      result = described_class.grep(handle: stored[:handle], regex: 'hit', limit: 999)
      expect(result[:matches].length).to eq(50)
      expect(result[:next_offset]).to eq(200)
      expect { described_class.grep(handle: stored[:handle], regex: '[') }.to raise_error(RegexpError)
      expect { described_class.grep(handle: stored[:handle], regex: 'hit', offset: -1) }.to raise_error(ArgumentError)
    end

    it 'interrupts expensive regexes on a giant unterminated line' do
      stored = described_class.spill(bytes: "#{'a' * 2047}!", session_id: 'timeout')
      expect { described_class.grep(handle: stored[:handle], regex: '(a+)\\1+$') }.to raise_error(Regexp::TimeoutError)
    end

    it 'rejects traversal, symlink directories, and short digest collisions' do
      expect { described_class.spill(bytes: 'x', session_id: '../escape') }.to raise_error(ArgumentError)
      stored = described_class.spill(bytes: 'x', session_id: 'safe')
      File.binwrite(stored[:path], 'different')
      expect { described_class.spill(bytes: 'x', session_id: 'safe') }.to raise_error(/collision/)
      expect(File.binread(stored[:path])).to eq('different')
      File.symlink(File.dirname(stored[:path]), File.join(described_class::ROOT, 'link'))
      expect { described_class.spill(bytes: 'x', session_id: 'link') }.to raise_error(/symlink/)
    end
  end

  it 'lists artifacts for a session id' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', dir)
      src = File.join(dir, 'loot.txt')
      File.write(src, 'x')
      described_class.register(session_id: 'sess1', path: src, kind: 'loot')
      rows = described_class.list(session_id: 'sess1')
      expect(rows.first[:kind]).to eq('loot')
    end
  end

  it 'greps an artifact by regex' do
    Dir.mktmpdir do |dir|
      src = File.join(dir, 'dump.txt')
      File.write(src, "nop\ncall system\nret\n")
      hits = described_class.read_page(path: src, grep: 'call.*system')
      expect(hits[:matches].first[:text]).to eq('call system')
      expect(hits[:matches].first[:line]).to eq(2)
    end
  end

  it 'round-trips put then get by sha256' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'art'))
      stored = described_class.put(bytes: 'pcap-bytes', kind: 'pcap', tags: ['net'])
      got = described_class.get(sha256: stored[:sha256])
      expect(got[:body]).to include('pcap-bytes')
      expect(stored[:tags]).to include('net')
    end
  end
end
