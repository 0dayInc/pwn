# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::AI::Agent::RequestRuntime, 'tool result key parity' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
  end

  after do
    Thread.current[:pwn_request_runtime] = nil
    Thread.current[:pwn_artifact_contract] = nil
  end

  [
    [{ ok: false }, 'uncertain'],
    [{ 'ok' => false }, 'uncertain'],
    [{ exit: 7, stdout: '' }, 'failed'],
    [{ 'exit' => 7, 'stdout' => '' }, 'failed']
  ].each_with_index do |(result, state), index|
    it "preserves failure and withholds artifact credit for result variant #{index}" do
      path = File.join(@tmp, 'partial.txt')
      runtime = described_class.new(request: "Write #{path}", session_id: 'key-parity', artifact_root: @tmp, trace: false)
      Thread.current[:pwn_request_runtime] = runtime
      Thread.current[:pwn_artifact_contract] = runtime.contract
      call = { name: 'fixture', args: { path: path }, effect: :write, action_id: 'first' }
      returned = runtime.execute_tool(call) do
        File.write(path, 'partial effect')
        result
      end

      expect(returned).to eq(result)
      expect(runtime.events.last[:state]).to eq(state)
      expect(runtime.observations).to be_empty
      if state == 'uncertain'
        denied = runtime.execute_tool(call) { raise 'must not replay an uncertain mutation' }
        expect(denied).to include(error: 'uncertain_side_effect')
      end
    end
  end
end
