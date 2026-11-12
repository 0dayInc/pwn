# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Policy, 'explicit confidence' do
  include_context 'pwn tmp sandbox'

  it 'does not upgrade zero confidence to a full terminal reward' do
    described_class.begin_episode(session_id: 'fixture', request: 'check the fixture')
    step = described_class.observe_step(session_id: 'fixture', action: 'shell', action_id: 'checked', ok: true)
    result = described_class.finish(session_id: 'fixture', score: 1.0, confidence: 0.0,
                                    attribution: { source: 'independent_verifier', verified_action_ids: ['checked'] })
    expect(result[:terminal_reward]).to eq(0.0)
    expect(described_class.q(state: step[:state], action: 'shell')).to eq(0.0)
  end
end
