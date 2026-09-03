# frozen_string_literal: true

require 'spec_helper'
require 'json'

describe PWN::AI::Agent::Dispatch do
  it 'classifies effect from tool name and argv, never from stdout' do
    expect(described_class.effect(name: 'shell', args: { command: 'ls /tmp' })).to eq :read
    expect(described_class.effect(name: 'shell', args: { command: 'cat README.md' })).to eq :read
    expect(
      described_class.effect(name: 'shell', args: { command: 'echo hi > /tmp/x.txt' })
    ).to eq :write
    expect(
      described_class.effect(
        name: 'shell',
        args: { command: "python3 -c \"open('/tmp/x.txt','w').write('complete')\"" }
      )
    ).to eq :write
    expect(
      described_class.effect(name: 'pwn_eval', args: { code: 'File.write("/tmp/a", "b")' })
    ).to eq :write
    expect(
      described_class.effect(
        name: 'pwn_eval',
        args: { code: 'PWN::Plugins::TransparentBrowser.open(browser_type: :chrome)' }
      )
    ).to eq :browse
    expect(described_class.effect(name: 'memory_recall', args: { query: 'docs' })).to eq :recall
    expect(described_class.effect(name: 'memory_remember', args: { key: 'sop' })).to eq :store
    expect(described_class.effect(name: 'learning_note_outcome', args: { task: 'x' })).to eq :store
    expect(
      described_class.effect(
        name: 'shell',
        args: {
          command: "cat >> ~/.pwn/logs/pwn-ai-DEBUG-2026-09-03.md <<'EOF'\n" \
                   "ToolGuard, TransparentBrowser, and devtools are strengths.\nEOF"
        }
      )
    ).to eq :write
    src = File.read(described_class.method(:effect).source_location.first)
    expect(src).to match(/def self\.effect/)
  end

  it 'stamps effect on Dispatch.call JSON' do
    PWN::AI::Agent::Registry.discover
    out = described_class.call(
      tool_call: {
        id: 't1',
        type: 'function',
        function: { name: 'shell', arguments: JSON.generate(command: 'echo effect_stamp_ok') }
      }
    )
    parsed = JSON.parse(out, symbolize_names: true)
    expect(parsed[:success]).to eq true
    expect(parsed[:effect].to_s).to eq 'read'
    expect(parsed.dig(:result, :stdout).to_s).to include('effect_stamp_ok')
  end
end
