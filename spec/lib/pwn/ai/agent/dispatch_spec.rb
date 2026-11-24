# frozen_string_literal: true

require 'spec_helper'
require 'json'

describe PWN::AI::Agent::Dispatch do
  describe 'reviewed cross-session memory saves' do
    include_context 'pwn tmp sandbox'

    let(:proposal) { { key: 'display_units', value: 'Use °C', category: 'preference' } }
    let(:runtime_options) { { request: 'Remember my display preference', session_id: 'review', request_id: 'memory', artifact_root: File.join(@tmp, 'requests'), trace: false } }
    let(:runtime) { PWN::AI::Agent::RequestRuntime.new(runtime_options) }

    around do |example|
      previous = [Thread.current[:pwn_review_memory], Thread.current[:pwn_request_runtime]]
      Thread.current[:pwn_review_memory] = nil
      example.run
    ensure
      Thread.current[:pwn_review_memory], Thread.current[:pwn_request_runtime] = previous
    end

    before do
      allow(Dir).to receive(:home).and_return(@tmp)
      PWN::AI::Agent::Registry.discover
      Thread.current[:pwn_request_runtime] = runtime
      expect(PWN::Plugins::Vault).not_to receive(:expand)
      expect(PWN::Plugins::Vault).not_to receive(:redact)
    end

    def save_memory(fields)
      call = { id: 'save-preference', function: { name: 'memory_remember', arguments: fields } }
      JSON.parse(described_class.call(tool_call: call), symbolize_names: true)
    end

    it 'saves only the reviewed fields, with a durable completion and independent file readback' do
      seen = []
      Thread.current[:pwn_review_memory] = lambda do |fields|
        seen << fields
        expect(fields).to be_frozen
        expect(fields.values).to all(be_frozen)
        expect(File).not_to exist(PWN::Memory::MEMORY_FILE)
        true
      end
      expect(save_memory(proposal)).to eq(success: true, effect: 'store', result: { saved: true })
      expect(seen).to eq([proposal])
      expect(JSON.parse(File.read(PWN::Memory::MEMORY_FILE)).fetch('display_units')).to include('value' => 'Use °C', 'category' => 'preference')
      expect(runtime.events.last).to include(phase: 'end', state: 'completed', action_id: 'save-preference')
      expect(runtime.blocker).to be_nil
    end

    it 'does not start a write on missing review, decline, or a self-approved tool payload' do
      expect(save_memory(proposal)).to include(success: false, result: include(execution_state: 'not_started'))
      Thread.current[:pwn_review_memory] = ->(_fields) { false }
      expect(save_memory(proposal)).to include(success: false, result: include(execution_state: 'not_started'))
      reviewer = double('operator review')
      expect(reviewer).not_to receive(:call)
      Thread.current[:pwn_review_memory] = reviewer
      expect(save_memory(proposal.merge(operator_ack: true))).to include(success: false)
      expect(save_memory(proposal.merge(value: '{{vault:fixture}}'))).to include(success: false)
      expect(File).not_to exist(PWN::Memory::MEMORY_FILE)
      expect(runtime.events).to be_empty
    end

    it 'distinguishes lock denial before mutation from a lost receipt after a write and never replays the latter' do
      Thread.current[:pwn_review_memory] = ->(_fields) { true }
      allow(File).to receive(:open).and_call_original
      allow(File).to receive(:open).with("#{PWN::Memory::MEMORY_FILE}.write.lock", anything, anything).and_raise(Errno::EACCES)
      expect(save_memory(proposal)).to include(success: false, result: include(execution_state: 'not_started'))
      expect(runtime.blocker).to be_nil
      expect(File).not_to exist(PWN::Memory::MEMORY_FILE)

      allow(File).to receive(:open).with("#{PWN::Memory::MEMORY_FILE}.write.lock", anything, anything).and_call_original
      allow(PWN::Memory).to receive(:remember).and_wrap_original do |writer, **options|
        writer.call(**options)
        raise Errno::EACCES, 'after write'
      end
      expect(save_memory(proposal)).to include(success: false)
      expect(PWN::Memory.load.fetch(:display_units)).to include(value: 'Use °C')
      restored = PWN::AI::Agent::RequestRuntime.new(runtime_options.merge(resume: true))
      Thread.current[:pwn_request_runtime] = restored
      expect(restored.blocker).to include('Uncertain side effect: memory_remember')
      expect(save_memory(proposal)).to include(success: false, result: include(error: 'uncertain_side_effect'))
      expect(PWN::Memory).to have_received(:remember).once
    end
  end

  it 'does not replay a timed-out real shell mutation after restoring its request checkpoint' do
    Dir.mktmpdir do |root|
      work = File.join(root, 'work')
      FileUtils.mkdir_p(work)
      allow(PWN::Plugins::AISandbox).to receive(:workspace).and_return(work)
      options = { request: 'Write counter', session_id: 'timeout', request_id: 'fixture', artifact_root: File.join(root, 'control'), trace: false }
      runtime = PWN::AI::Agent::RequestRuntime.new(options)
      Thread.current[:pwn_request_runtime] = runtime
      PWN::AI::Agent::Registry.discover
      call = { id: 'mutation', function: { name: 'shell', arguments: { command: "printf effect >> #{work}/counter; sleep 3", timeout: 1 } } }
      first = JSON.parse(described_class.call(tool_call: call, scope_policy: { enabled: false }))
      expect(first.dig('result', 'error')).to include('timeout')
      Thread.current[:pwn_request_runtime] = PWN::AI::Agent::RequestRuntime.new(options.merge(resume: true))
      second = JSON.parse(described_class.call(tool_call: call, scope_policy: { enabled: false }))
      expect(second['success']).to be false
      expect(second.dig('result', 'error')).to eq('uncertain_side_effect')
      expect(File.read(File.join(work, 'counter'))).to eq('effect')
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
