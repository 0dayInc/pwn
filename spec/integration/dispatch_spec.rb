# frozen_string_literal: true

require 'spec_helper'
require 'json'

# ─────────────────────────────────────────────────────────────────────────────
#  #2 — tolerant dispatch (local-model repair paths).
#
#  repair_name / parse_args are exactly the kind of thing that regresses
#  silently: a frontier engine never touches them, so a break only shows
#  up as "the ollama harness got dumb". NON-BLOCKING: registers a
#  throwaway tool with a pure-ruby handler in `before`.
# ─────────────────────────────────────────────────────────────────────────────

RSpec.describe 'PWN::AI::Agent::Dispatch — tolerant dispatch', :aggregate_failures do
  include_context 'pwn tmp sandbox'

  let(:registry) { PWN::AI::Agent::Registry }
  let(:dispatch) { PWN::AI::Agent::Dispatch }
  let(:mistakes) { PWN::AI::Agent::Mistakes }

  before do
    registry.discover(force: true)
    registry.register(
      name: 'spec_echo',
      toolset: 'terminal',
      schema: {
        name: 'spec_echo',
        description: 'echo the payload back',
        parameters: { type: 'object', properties: { payload: { type: 'string' } }, required: %w[payload] }
      },
      handler: ->(a) { { echoed: a[:payload] } }
    )
    registry.register(
      name: 'spec_boom',
      toolset: 'terminal',
      schema: { name: 'spec_boom', description: 'always raises', parameters: { type: 'object', properties: {} } },
      handler: ->(_) { raise 'kaboom' }
    )
  end

  after do
    # Registry is process-global — don't leak throwaway tools into
    # documentation_sync_spec / tool_registry_spec when the whole
    # integration suite runs in one process.
    registry.instance_variable_get(:@entries).delete('spec_echo')
    registry.instance_variable_get(:@entries).delete('spec_boom')
  end

  def call(name, args)
    JSON.parse(dispatch.call(tool_call: { function: { name: name, arguments: args } }))
  end

  describe '.repair_name' do
    it 'levenshtein-matches near-miss names to registered tools' do
      expect(dispatch.repair_name(name: 'shel')).to eq('shell')
      expect(dispatch.repair_name(name: 'pwn-eval')).to eq('pwn_eval')
      expect(dispatch.repair_name(name: 'memoryremember')).to eq('memory_remember')
      expect(dispatch.repair_name(name: 'spec_ech')).to eq('spec_echo')
    end

    it 'returns nil when nothing is close enough' do
      expect(dispatch.repair_name(name: 'xyzzy_quux_frobozz')).to be_nil
      expect(dispatch.repair_name(name: '')).to be_nil
    end

    it 'fingerprints every successful repair into Mistakes(tool: tool_name)' do
      dispatch.repair_name(name: 'pwn-eval')
      expect(mistakes.for_tool(tool: 'tool_name')).not_to be_empty
    end
  end

  describe '.call — argument parsing' do
    it 'accepts valid JSON, a raw Hash, and empty args' do
      expect(call('spec_echo', '{"payload":"a"}')).to include('success' => true, 'result' => { 'echoed' => 'a' })
      expect(call('spec_echo', { 'payload' => 'b' })).to include('success' => true, 'result' => { 'echoed' => 'b' })
      expect(call('spec_echo', nil)).to include('success' => true)
    end

    it 'tolerantly parses trailing-comma / single-quoted JSON' do
      expect(call('spec_echo', '{"payload":"a",}')).to include('result' => { 'echoed' => 'a' })
      expect(call('spec_echo', "{'payload':'a'}")).to include('result' => { 'echoed' => 'a' })
    end

    it 'wraps a bare scalar as the sole required parameter' do
      expect(call('spec_echo', 'bare words')).to include('result' => { 'echoed' => 'bare words' })
    end
  end

  describe '.call — error surface' do
    it 'returns {"error":"unknown tool: …"} for an unrepairable name' do
      expect(call('xyzzy_quux_frobozz', '{}')).to include('error' => a_string_matching(/unknown tool/))
    end

    it 'never propagates a handler exception — returns {success:false, error:, backtrace:}' do
      out = call('spec_boom', '{}')
      expect(out['success']).to be false
      expect(out['error']).to match(/RuntimeError.*kaboom/)
      expect(out['backtrace']).to be_an(Array)
    end

    it 'routes through repair_name when the model misspells a tool' do
      expect(call('spec_ech', '{"payload":"x"}')).to include('result' => { 'echoed' => 'x' })
    end
  end
end
