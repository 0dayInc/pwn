# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'pwn/redaction'

RSpec.describe 'Persistence redaction' do
  it 'rejects deep and cyclic containers before logging or inspecting sensitive fields' do
    cycle = { password: 'harmless-private-fixture' }
    cycle[:self] = cycle
    deep = 'leaf'
    10_000.times { deep = [deep] }
    [cycle, deep, { password: deep }].each do |value|
      expect { PWN::Redaction.redact(value: value) }.to raise_error(JSON::NestingError, /nesting limit/)
    end
    shared = { password: 'harmless-private-fixture' }
    expect(PWN::Redaction.redact(value: [shared, shared]).to_s).not_to include('harmless-private-fixture')
    expect(shared[:password]).to eq('harmless-private-fixture')
    boundary = 'public'
    100.times { boundary = [boundary] }
    expect(JSON.generate(PWN::Redaction.redact(value: boundary))).to eq(JSON.generate(boundary))
    expect { PWN::Redaction.redact(value: [boundary]) }.to raise_error(JSON::NestingError)
  end

  it 'redacts all session fields before capping, without consulting credential files or permitting an opt-out' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Sessions::SESSIONS_DIR', dir)
      expect(PWN::Plugins::Vault).not_to receive(:redact)
      allow(PWN::Env).to receive(:dig).with(:ai, :agent, :redact_transcripts).and_return(false)
      secret = 'ASIAABCDEFGHIJKLMNOP'
      session = PWN::Sessions.create(id: 'safe', title: secret)
      PWN::Sessions.append(session_id: 'safe', role: secret, content: { nested: [{ api_key: 'fixture-only' }, secret] })
      PWN::Sessions.append(session_id: 'safe', role: 'tool', content: "#{'x' * 1490} -----BEGIN PRIVATE KEY-----\n#{'body' * 500}\n-----END PRIVATE KEY-----")
      raw = File.read(session[:path])
      expect(raw).not_to include(secret, 'fixture-only', 'PRIVATE KEY', 'body')
      expect(raw).to include('[REDACTED:aws:', '[REDACTED:api_key:')
    end
  end

  it 'sanitizes regular, learning, debug, mirror, stderr and fallback writes' do
    Dir.mktmpdir do |dir|
      secret = 'ASIAABCDEFGHIJKLMNOP'
      path = File.join(dir, 'log')
      allow(File).to receive(:open).and_call_original
      allow(File).to(receive(:open).with('/tmp/pwn.log', 'a').and_wrap_original { |m, _, mode| m.call(path, mode) })
      PWN::Plugins::Log.append(level: :info, msg: secret, which_self: secret)
      PWN::Plugins::Log.append(level: :info, msg: { api_key: 'nested-fixture-only' })
      expect(File.read(path)).not_to include(secret, 'nested-fixture-only')
      expect(File.read(path)).to include('[REDACTED:aws:')
      PWN::Plugins::Log.start_debug(path: path)
      PWN::Plugins::Log.progress(msg: secret)
      PWN::Plugins::Log.mirror_tui!(msg: secret)
      PWN::Plugins::Log.capture_stderr!(text: "#{secret}\n")
      allow(PWN::Plugins::Log).to receive(:progress).and_return(false)
      PWN::Plugins::Log.note_interrupt!(where: secret)
      PWN::Plugins::Log.stop_debug
      expect(File.read(path)).not_to include(secret)
      expect(File.read(path)).to include('[REDACTED:aws:')
    ensure
      PWN::Plugins::Log.stop_debug
    end
  end

  it 'sanitizes learning payloads, logger output, compaction and retention artifacts before writing' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Sessions::SESSIONS_DIR', File.join(dir, 'sessions'))
      FileUtils.mkdir_p(PWN::Sessions::SESSIONS_DIR)
      secret = 'AKIAABCDEFGHIJKLMNOP'
      io = StringIO.new
      original = $stdout
      $stdout = io
      PWN::Plugins::PWNLogger.create.info(secret)
      PWN::Plugins::PWNLogger.create.info({ api_key: 'logger-fixture-only' })
      $stdout = original
      expect(io.string).not_to include(secret, 'logger-fixture-only')
      path = File.join(dir, 'learning.json')
      allow(File).to receive(:open).and_call_original
      allow(File).to(receive(:open).with(%r{\A/tmp/pwn-ai-.*\.json\z}, 'w').and_wrap_original { |m, _, mode| m.call(path, mode) })
      PWN::Plugins::Log.append(level: :learning, msg: [{ api_key: 'fixture-only', body: secret }])
      expect(File.read(path)).not_to include(secret, 'fixture-only')
      transcript = File.join(PWN::Sessions::SESSIONS_DIR, 'old.jsonl')
      File.write(transcript, "#{JSON.generate(role: 'tool', content: "#{secret} #{'x' * 200}")}\n")
      PWN::Sessions.send(:compact_transcript!, path: transcript, tool_max: 50)
      expect(File.read(transcript)).not_to include(secret)
      File.write(transcript, "#{JSON.generate(role: 'user', content: secret)}\n")
      File.utime(Time.at(0), Time.at(0), transcript)
      PWN::Sessions.retain(days: 1)
      expect(Zlib::GzipReader.open("#{transcript}.gz", &:read)).not_to include(secret)
    ensure
      $stdout = original if original
    end
  end

  it 'exports valid redacted JSONL with checksums of the exported bytes' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Sessions::SESSIONS_DIR', File.join(dir, 'sessions'))
      session = PWN::Sessions.create(id: 'exported')
      row = { role: 'user', content: "-----BEGIN PRIVATE KEY-----\nfixture-only\n-----END PRIVATE KEY-----" }
      File.write(session[:path], "#{JSON.generate(row)}\n")
      exported = PWN::Sessions.export(session_id: 'exported')
      unpacked = File.join(dir, 'unpacked')
      FileUtils.mkdir_p(unpacked)
      expect(system('tar', '-xzf', exported[:path], '-C', unpacked)).to be(true)
      body = File.read(File.join(unpacked, 'exported.jsonl'))
      expect(JSON.parse(body)['content']).to match(/\A\[REDACTED:pem:/)
      expect(body).not_to include('fixture-only')
      manifest = JSON.parse(File.read(File.join(unpacked, 'manifest.json')))
      expect(manifest['exported.jsonl']).to eq(Digest::SHA256.hexdigest(body))
    end
  end

  it 'buffers fragmented stderr secrets and multi-line PEM blocks before persistence' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'stream.log')
      PWN::Plugins::Log.start_debug(path: path)
      %W[ASIA ABCDEFGHIJKLMNOP\n].each { |part| PWN::Plugins::Log.capture_stderr!(text: part) }
      pem = "-----BEGIN PRIVATE KEY-----\nfixture-private-material\n-----END PRIVATE KEY-----\n"
      pem.lines.each { |line| PWN::Plugins::Log.capture_stderr!(text: line) }
      PWN::Plugins::Log.stop_debug
      body = File.read(path)
      expect(body).not_to include('ABCDEFGHIJKLMNOP', 'fixture-private-material')
      expect(body).to include('[REDACTED:aws:', '[REDACTED:pem:')
    ensure
      PWN::Plugins::Log.stop_debug
    end
  end

  it 'redacts complete PEM, JWT, AWS and authorization values with stable hash8 markers' do
    samples = {
      'pem' => "-----BEGIN PRIVATE KEY-----\nfixture-body\n-----END PRIVATE KEY-----",
      'jwt' => 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJl',
      'aws' => 'ASIAABCDEFGHIJKLMNOP',
      'authorization' => 'Authorization: Basic Zml4dHVyZTpwYXNz'
    }
    expect(defined?(PWN::Redaction)).to be_truthy
    samples.each do |kind, value|
      marker = "[REDACTED:#{kind}:#{Digest::SHA256.hexdigest(value)[0, 8]}]"
      expect(PWN::Redaction.redact(value: value)).to eq(marker)
      expect(PWN::Redaction.redact(value: marker)).to eq(marker)
    end
  end
end
