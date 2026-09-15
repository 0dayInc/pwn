# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'tmpdir'
require 'socket'

describe 'pwn-ai 2026-09-15 harness patches' do
  it 'allows a heredoc range and markdown ellipsis but denies a trailing bare token' do
    ok = <<~CMD
      cat <<'EOF'
      1...10 and wait...
      EOF
    CMD
    expect(PWN::AI::Agent::ToolGuard.placeholder?(text: ok)).to eq(false)
    expect(PWN::AI::Agent::ToolGuard.placeholder?(text: "echo hi\n...\n")).to eq(true)
    expect(PWN::AI::Agent::ToolGuard.placeholder?(text: 'echo hi ...')).to eq(false)
    expect(PWN::AI::Agent::ToolGuard.placeholder?(text: '[ ... ]')).to eq(true)
    expect(PWN::AI::Agent::ToolGuard.placeholder?(text: '...', placeholder_ok: true)).to eq(false)
  end

  it 'names the colliding payload hash and normalized fields on identical retry' do
    3.times do
      n = PWN::AI::Agent::Loop.send(:note_same_payload!, name: 'shell', args: { command: "echo  hi\n" })
      next if n < 3

      raw = PWN::AI::Agent::Loop.send(:checkpoint_result, name: 'shell', args: { command: "echo  hi\n" })
      body = JSON.parse(raw)
      expect(body['payload_hash']).to match(/\A[0-9a-f]{16}\z/)
      expect(body['normalized_fields']).to include('command')
      expect(body['error']).to include("hash=#{body['payload_hash']}")
    end
  end

  it 'injects extracted output paths into the system prompt' do
    prompt = PWN::AI::Agent::PromptBuilder.build(request: 'Write the report to /tmp/pwn-harness-out.md')
    expect(prompt).to include('DELIVERABLES')
    expect(prompt).to include('/tmp/pwn-harness-out.md')
  end

  it 'expects a regex over a PTY session' do
    id = PWN::Plugins::ProcessTube.spawn(cmd: ['printf', "uid=0(root)\n"])[:id]
    out = PWN::Plugins::ProcessTube.expect(id: id, pattern: /uid=\d+/, timeout: 2, strip_ansi: true)
    expect(out[:matched]).to match(/uid=/)
    PWN::Plugins::ProcessTube.close(id: id)
  end

  it 'consumes matched PTY output so a second expect needs new bytes' do
    id = PWN::Plugins::ProcessTube.spawn(cmd: ['printf', "uid=0(root)\nready\n"])[:id]
    first = PWN::Plugins::ProcessTube.expect(id: id, pattern: /uid=\d+/, timeout: 2)
    second = PWN::Plugins::ProcessTube.expect(id: id, pattern: /ready/, timeout: 2)
    expect(first[:matched]).to match(/uid=/)
    expect(second[:matched]).to include('ready')
    PWN::Plugins::ProcessTube.close(id: id)
  end

  it 'runs a three-node job graph with partials on failure' do
    Dir.mktmpdir('jobs') do |dir|
      result = PWN::Plugins::Jobs.graph(
        artifact_dir: dir,
        jobs: [
          { id: 'a', command: 'echo enum > a.txt' },
          { id: 'b', command: 'echo httpx >> a.txt', needs: ['a'] },
          { id: 'c', command: 'echo nuclei >> a.txt', needs: ['b'] }
        ]
      )
      expect(result[:ok]).to eq(true)
      expect(File.read(File.join(dir, 'a.txt'))).to include('nuclei')
    end
  end

  it 'retains partials when an upstream job fails' do
    Dir.mktmpdir('jobs-fail') do |dir|
      result = PWN::Plugins::Jobs.graph(
        artifact_dir: dir,
        jobs: [
          { id: 'a', command: 'false' },
          { id: 'b', command: 'echo b', needs: ['a'] },
          { id: 'c', command: 'echo c', needs: ['b'] }
        ]
      )
      expect(result[:jobs]['a'][:ok]).to eq(false)
      expect(result[:jobs]['b'][:skipped]).to eq(true)
      expect(result[:jobs]['c'][:skipped]).to eq(true)
    end
  end

  it 'enforces a per-job timeout' do
    Dir.mktmpdir('jobs-to') do |dir|
      result = PWN::Plugins::Jobs.graph(
        artifact_dir: dir,
        jobs: [{ id: 'slow', command: 'sleep 2', timeout: 0.05 }]
      )
      expect(result[:jobs]['slow'][:timeout]).to eq(true)
    end
  end

  it 'dedups fuzz crashes and scores the minimized file' do
    Dir.mktmpdir('crash') do |dir|
      a = File.join(dir, '1')
      b = File.join(dir, '2')
      File.binwrite(a, 'AAAAAAAAB')
      File.binwrite(b, 'AAAAAAAAB')
      rows = PWN::Plugins::Fuzz.triage(dir: dir)
      expect(rows.length).to eq(1)
      expect(rows.first[:count]).to eq(2)
      expect(rows.first[:exploitability]).to eq('pc_control_candidate')
    end
  end

  it 'raises on an offline corpus cache miss' do
    Dir.mktmpdir('corpus-miss') do |dir|
      stub_const('PWN::Corpus::ROOT', dir)
      expect { PWN::Corpus.get(name: :subdomains_top1m, offline: true) }.to raise_error(IOError, /offline/)
    end
  end

  it 'parses nmap XML without requiring a live scan' do
    Dir.mktmpdir('nmap') do |dir|
      xml = File.join(dir, 'scan.xml')
      File.write(xml, <<~XML)
        <?xml version="1.0"?>
        <nmaprun>
          <host><address addr="10.0.0.1" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>
          </host>
        </nmaprun>
      XML
      allow(PWN::Engagement).to receive(:warn_unless_in_scope).and_return({ ok: true })
      allow(PWN::Engagement).to receive(:merge_scan)
      row = PWN::Plugins::NmapIt.scan(xml: xml, engagement: false)
      expect(row[:hosts].first[:host]).to eq('10.0.0.1')
      expect(row[:ports].first[:port]).to eq(22)
    end
  end

  it 'health lines include Plugin-Degradation anchors' do
    doc = File.read(File.join(__dir__, '../../../../../documentation/Plugin-Degradation.md'))
    PWN::Plugins::PreflightChecker::PLUGIN_DEPS.each_key do |plugin|
      anchor = plugin.to_s.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/\A-+|-+\z/, '')
      expect(doc).to include("## #{anchor}")
    end
  end
end
