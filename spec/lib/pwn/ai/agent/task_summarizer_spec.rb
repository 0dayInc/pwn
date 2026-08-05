# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::TaskSummarizer do
  it 'fresh method should exist' do
    expect(described_class).to respond_to :fresh
  end

  it 'record! method should exist' do
    expect(described_class).to respond_to :record!
  end

  it 'emit! method should exist' do
    expect(described_class).to respond_to :emit!
  end

  it 'flush! method should exist' do
    expect(described_class).to respond_to :flush!
  end

  it 'enabled? method should exist' do
    expect(described_class).to respond_to :enabled?
  end

  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'coalesces tool bursts into a summary line' do
    allow(PWN::Env).to receive(:dig).and_call_original
    allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_every).and_return(2)
    allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_interval_s).and_return(9_999)
    allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary).and_return(true)
    allow(PWN::Env).to receive(:dig).with(:ai, :agent, :task_summary_verbose).and_return(false)

    state = described_class.fresh(request: 'fix rake')
    expect(described_class.record!(state, 'shell', 'rake', '{success:true}')).to be_nil
    line = described_class.record!(state, 'shell', 'rake 2>&1', '{success:true}')
    expect(line).to be_a(String)
    expect(line).to include('in progress')
    expect(line).to include('shell')
    expect(state[:total]).to eq 2

    fin = described_class.flush!(state)
    expect(fin).to include('done')
    expect(fin).to include('2 tools')
  end
end
