# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::AI::Agent::Mission, 'failed DAG resume accounting' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
  end

  it 'keeps a failed resumed step out of completed-step state and the operator report' do
    steps = [{ id: 'probe', tool: 'shell', args: { command: 'exit 7', timeout: 5 } }]
    dag = PWN::AI::Agent::TaskDAG.plan(request: 'probe status', steps: steps)
    PWN::AI::Agent::TaskDAG.execute(dag: dag, root: @tmp, run_id: 'failed-resume')
    described_class.begin!(id: 'probe', request: 'probe status')
    described_class.bind_run!(id: 'probe', run_id: 'failed-resume', root: @tmp)

    report = described_class.resume_run(id: 'probe')

    expect(report[:ok]).to be false
    expect(described_class.current(id: 'probe')[:last_completed_step]).to be_nil
    expect(described_class.done?(id: 'probe')).to be false
    expect(report[:text]).not_to include('Completed steps: probe')
    expect(report[:text]).to include('Failed steps: probe')
  end
end
