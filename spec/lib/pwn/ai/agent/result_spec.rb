# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Agent::Result do
  around do |example|
    Dir.mktmpdir('pwn-result-') do |dir|
      @artifact_root = dir
      example.run
    end
  end

  before { stub_const('PWN::Plugins::ArtifactRegistry::ROOT', @artifact_root) }

  it 'spills real Dispatch output before redaction while retaining failure status' do
    PWN::AI::Agent::Registry.discover
    file = File.join(@artifact_root, 'strings.txt')
    size = 50 * 1024 * 1024
    row = "strings payload\n"
    content = (row * ((size / row.bytesize) + 1)).byteslice(0, size)
    File.binwrite(file, content)
    response = JSON.parse(PWN::AI::Agent::Dispatch.call(
                            tool_call: { function: { name: 'shell', arguments: { command: "cat #{file}; exit 7", timeout: 5 } } },
                            scope_path: File.join(@artifact_root, 'absent.yml')
                          ))
    result = response.fetch('result')
    expect(result['exit']).to eq(7)
    expect(result['artifact']).to be_a(Hash)
    saved = JSON.parse(File.binread(result['artifact']['path']))
    expect(saved['stdout']).to eq(content)
    expect(saved['exit']).to eq(7)
    expect(PWN::AI::Agent::Loop.send(:retryable_execution_failure?, raw: JSON.generate(response))).to eq(true)
  end

  it 'pages and searches through actual tool schemas within the smallest inline budget' do
    PWN::AI::Agent::Registry.discover
    allow(PWN::Env).to receive(:dig).and_call_original
    allow(PWN::Env).to receive(:dig).with(:ai, :agent, :artifact_max_tokens).and_return(1024)
    raw = ("\x00\xff".b * 4096) + "needle-at-end\n".b
    summary = JSON.parse(described_class.condition(content: raw, session_id: 'roundtrip'))
    handle = summary.fetch('artifact').fetch('handle')
    reconstructed = +''.b
    offset = 0
    messages = [{ role: 'system', content: 'Read the saved bytes.' }, { role: 'user', content: 'Inspect the dump.' }]
    loop do
      tc = { id: "page-#{offset}", function: { name: 'artifact_read', arguments: { handle: handle, offset: offset, length: 50_000_000 } } }
      response = PWN::AI::Agent::Dispatch.call(tool_call: tc, scope_path: File.join(@artifact_root, 'absent.yml'))
      safe = described_class.condition(content: response)
      expect(safe.bytesize).to be <= described_class.token_limit
      page = JSON.parse(safe).fetch('result')
      expect(page).not_to have_key('artifact')
      reconstructed << Base64.strict_decode64(page.fetch('body'))
      messages << { role: 'assistant', content: '', tool_calls: [tc] }
      messages << { role: 'tool', tool_call_id: tc[:id], content: safe }
      PWN::AI::Agent::Loop.send(:compact_history!, messages: messages)
      expect(messages.length).to be <= 14
      break if page.fetch('eof')

      expect(page.fetch('next_offset')).to be > offset
      offset = page.fetch('next_offset')
    end
    expect(reconstructed).to eq(raw)
    response = PWN::AI::Agent::Dispatch.call(
      tool_call: { function: { name: 'artifact_grep', arguments: { handle: handle, regex: 'needle-at-end' } } },
      scope_path: File.join(@artifact_root, 'absent.yml')
    )
    safe = described_class.condition(content: response)
    expect(safe.bytesize).to be <= described_class.token_limit
    expect(JSON.parse(safe).dig('result', 'matches')).not_to be_empty
  end

  it 'preserves oversized results byte for byte instead of truncating' do
    raw = ("strings row\n" * 10_000).b + "\x00\xff".b
    summary = JSON.parse(described_class.condition(content: raw, session_id: 'paging-test'))
    expect(summary['artifact']['handle']).to match(%r{\Apaging-test/[0-9a-f]{8}\.bin\z})
    expect(File.binread(summary['artifact']['path'])).to eq(raw)
    expect(summary['artifact']['sha256']).to eq(Digest::SHA256.hexdigest(raw))
    expect(summary['summary']).to include('artifact_read', 'artifact_grep')
    expect(JSON.generate(summary).bytesize).to be < described_class.token_limit
  end

  it 'spills above the configured conservative token bound' do
    allow(PWN::Env).to receive(:dig).and_call_original
    allow(PWN::Env).to receive(:dig).with(:ai, :agent, :artifact_max_tokens).and_return(2048)
    expect(described_class.condition(content: 'x' * 2048)).to eq('x' * 2048)
    expect(JSON.parse(described_class.condition(content: 'x' * 2049))['artifact']['bytes']).to eq(2049)
  end
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Result
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Result
    expect(help_response).to respond_to :help
  end

  it 'uses LOCAL_DEFAULT_MAX when active engine is ollama (0.3)' do
    allow(PWN::Env).to receive(:dig).and_call_original
    allow(PWN::Env).to receive(:dig).with(:ai, :active).and_return('ollama')
    allow(PWN::Env).to receive(:dig).with(:ai, :ollama, :result_max).and_return(nil)
    expect(described_class.default_max).to eq described_class::LOCAL_DEFAULT_MAX
    big = 'x' * 10_000
    out = described_class.condition(content: big)
    expect(out.length).to be < 10_000
    expect(out).to include('artifact_read')
  end
end
