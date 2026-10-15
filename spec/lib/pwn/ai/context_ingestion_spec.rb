# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Context do
  it 'rejects deep XML before recursive XPath, serialization, database writes or embeddings' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'deep.xml')
      valid = "#{'<root>' * 100}harmless-fixture#{'</root>' * 100}"
      File.write(path, valid)
      expect(described_class.send(:ingestion_records, source: path).first[:text]).to eq(valid)
      File.write(path, "#{'<root>' * 10_000}harmless-fixture#{'</root>' * 10_000}")
      expect(described_class).not_to receive(:ingestion_db)
      expect { described_class.ingest(path: path, root: dir) }.to raise_error(ArgumentError, /XML nesting limit/)
    end
  end

  it 'removes stale evidence when a source is emptied and re-ingested' do
    Dir.mktmpdir do |dir|
      file = File.join(dir, 'source.txt')
      opts = { root: File.join(dir, 'db'), endpoint: 'http://127.0.0.1:1', timeout: 1 }
      File.write(file, 'obsolete-marker')
      described_class.ingest(opts.merge(path: file))
      File.write(file, '')
      described_class.ingest(opts.merge(path: file))
      expect(described_class.retrieve(opts.merge(query: 'obsolete-marker'))[:chunks]).to eq([])
    end
  end

  it 'persists real Ollama vectors and ranks with the real sqlite-vec extension', :local_embeddings do
    Dir.mktmpdir do |dir|
      file = File.join(dir, 'tls.txt')
      File.write(file, 'An HTTPS server accepts encrypted TLS connections on port 443.')
      opts = { root: dir, endpoint: ENV.fetch('PWN_TEST_EMBED_ENDPOINT'), model: 'all-minilm' }
      expect(described_class.ingest(opts.merge(path: file))[:status]).to eq('ok')
      result = described_class.retrieve(opts.merge(query: 'TLS HTTPS service'))
      expect(result[:backend]).to eq('sqlite-vec')
      expect(result[:chunks].first[:source]).to eq(file)
      expect(result[:chunks].first[:score]).to be > 0
      database = SQLite3::Database.new(File.join(dir, 'default.db'))
      expect(JSON.parse(database.get_first_value('SELECT vector FROM chunks')).length).to be > 0
      database.close
    end
  end

  it 'ingests HAR, Burp, ZAP, source trees and an offline PacketFu pcap with auditable citations' do
    require 'packetfu'
    Dir.mktmpdir do |dir|
      input = File.join(dir, 'inputs')
      Dir.mkdir(input)
      File.write(File.join(input, 'capture.har'), JSON.generate(log: { entries: [{ request: { url: 'https://example.test/har-marker' } }] }))
      File.write(File.join(input, 'burp.xml'), '<items><item><request base64="true">R0VUIC9idXJwLW1hcmtlciBIVFRQLzEuMQ==</request></item></items>')
      File.write(File.join(input, 'zap.xml'), '<OWASPZAPReport><site name="zap-marker"><alerts><alertitem><alert>zap-finding</alert></alertitem></alerts></site></OWASPZAPReport>')
      File.write(File.join(input, 'source.rb'), "puts 'source-marker'\n")
      # Offline Ethernet frame in a real little-endian PCAP; no network traffic.
      frame = "#{(([0] * 12) + [0x88, 0xb5]).pack('C*')}pcap-marker"
      header = [0xa1b2c3d4, 2, 4, 0, 0, 65_535, 1].pack('VvvVVVV')
      File.binwrite(File.join(input, 'capture.pcap'), header + [0, 0, frame.bytesize, frame.bytesize].pack('VVVV') + frame)
      opts = { root: File.join(dir, 'db'), endpoint: 'http://127.0.0.1:1', timeout: 1 }
      result = described_class.ingest(opts.merge(path: input))
      expect(result[:chunks]).to be >= 5
      %w[har-marker burp-marker zap-finding source-marker pcap-marker].each do |marker|
        expect(described_class.retrieve(opts.merge(query: marker))[:chunks].map { |hit| hit[:text] }.join).to include(marker)
      end
    end
  end

  it 'rejects session traversal and XML entity declarations before persistence' do
    Dir.mktmpdir do |dir|
      file = File.join(dir, 'unsafe.xml')
      File.write(file, '<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>')
      expect { described_class.ingest(path: file, root: dir) }.to raise_error(ArgumentError, /DTD/)
      expect { described_class.retrieve(query: 'x', root: dir, session_id: '../outside') }.to raise_error(ArgumentError, /session/)
    end
  end

  it 'ingests actual nmap XML into sqlite and retrieves cited lexical evidence when Ollama is down' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'scan.xml')
      File.write(path, '<nmaprun><host><address addr="192.0.2.1"/><ports><port portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>')
      opts = { session_id: 'fixture', root: dir, endpoint: 'http://127.0.0.1:1', timeout: 1 }
      result = described_class.ingest(opts.merge(path: path))
      expect(result[:chunks]).to be > 0
      expect(result[:status]).to eq('degraded')
      hits = described_class.retrieve(opts.merge(query: 'https'))
      expect(hits[:chunks].first[:citation]).to include(path)
      expect(hits[:chunks].first[:text]).to include('443')
      expect(hits[:backend]).to eq('sqlite-lexical')
    end
  end
end
