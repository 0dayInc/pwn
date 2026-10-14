# frozen_string_literal: true

require 'spec_helper'
require 'json'

describe PWN::AI::Agent::Dispatch do
  it 'does not replay a timed-out real shell mutation after restoring its request checkpoint' do
    Dir.mktmpdir do |root|
      options = { request: 'Write counter', session_id: 'timeout', request_id: 'fixture', artifact_root: root, trace: false }
      runtime = PWN::AI::Agent::RequestRuntime.new(options)
      Thread.current[:pwn_request_runtime] = runtime
      PWN::AI::Agent::Registry.discover
      call = { id: 'mutation', function: { name: 'shell', arguments: { command: "printf effect >> #{root}/counter; sleep 3", timeout: 1 } } }
      first = JSON.parse(described_class.call(tool_call: call, scope_policy: { enabled: false }))
      expect(first.dig('result', 'error')).to include('timeout')
      Thread.current[:pwn_request_runtime] = PWN::AI::Agent::RequestRuntime.new(options.merge(resume: true))
      second = JSON.parse(described_class.call(tool_call: call, scope_policy: { enabled: false }))
      expect(second['success']).to be false
      expect(second.dig('result', 'error')).to eq('uncertain_side_effect')
      expect(File.read(File.join(root, 'counter'))).to eq('effect')
      expect(call.dig(:function, :arguments, :timeout)).to eq(1)
    end
  ensure
    Thread.current[:pwn_request_runtime] = nil
    Thread.current[:pwn_dispatch_budget] = nil
  end

  it 'rejects cyclic and overdeep validation schemas before stack exhaustion' do
    cycle = {}
    cycle[:properties] = cycle
    deep = {}
    10_000.times { deep = { properties: deep } }
    [cycle, deep].each do |schema|
      expect { described_class.send(:drop_required, node: schema) }.to raise_error(JSON::NestingError)
    end
  end

  it 'returns an actionable dispatch error for a cyclic schema without invoking the handler' do
    schema = { type: 'object' }
    schema[:properties] = schema
    handler = double('handler')
    entry = PWN::AI::Agent::Registry::Entry.new(name: 'stack_fixture', schema: { parameters: schema }, handler: handler)
    allow(PWN::AI::Agent::Registry).to receive(:lookup).with(name: 'stack_fixture').and_return(entry)
    allow(PWN::AI::Agent::Manifest).to receive(:load).and_return({})
    expect(handler).not_to receive(:call)
    response = JSON.parse(described_class.call(tool_call: { function: { name: 'stack_fixture', arguments: {} } }))
    expect(response['success']).to be(false)
    expect(response['error']).to include('JSON::NestingError', 'tool schema')
  end

  it 'classifies effect from tool name and argv, never from stdout' do
    expect(described_class.effect(name: 'shell', args: { command: 'ls /tmp' })).to eq :exclusive
    expect(described_class.effect(name: 'shell', args: { command: 'cat README.md' })).to eq :exclusive
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
    expect(parsed[:effect].to_s).to eq 'exclusive'
    expect(parsed.dig(:result, :stdout).to_s).to include('effect_stamp_ok')
  end

  it 'fails closed for an unattended mission without passing job tails to the gate' do
    allow(PWN::AI::Agent::Mission).to receive(:active).and_return(id: 'lab', unattended: true)
    allow(PWN::AI::Agent::Confirmation).to receive(:gate).and_return(success: false, code: 'ACK_DENY')
    described_class.call(
      tool_call: {
        function: { name: 'shell', arguments: JSON.generate(command: 'true') }
      }
    )
    expect(PWN::AI::Agent::Confirmation).to have_received(:gate).with(hash_including(unattended: true, ack_scope: true))
  end
end
