# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::TaskSummarizer, 'failed dispatch advancement' do
  include_context 'pwn tmp sandbox'

  it 'does not mark a failed write as completed because its error mentions File.write' do
    state = described_class.fresh(request: 'write the required report')
    state[:plan] = ['Write the report', 'Present the report']
    result = JSON.generate(success: false, error: 'File.write could not create report')
    described_class.record!(state: state, name: 'pwn_eval', args: { code: 'File.write(report, content)' }, result: result)
    expect(state[:events].last[:ok]).to be(false)
    expect(state[:plan_idx]).to eq(0)
  end

  it 'does not advance through the phase-handoff fallback after failed dispatches' do
    state = described_class.fresh(request: 'inspect then patch the report')
    state[:plan] = ['Inspect the report', 'Patch the report', 'Present the result']
    2.times do
      described_class.record!(state: state, name: 'shell', args: { command: 'sed -i replacement report' }, result: '{"success":false,"error":"fixture failure"}')
    end
    expect(state[:plan_idx]).to eq(0)
    expect(state[:last_prm_signal]).to eq(:hold_regress)
  end
end
