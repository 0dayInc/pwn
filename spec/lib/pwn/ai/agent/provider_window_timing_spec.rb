# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Loop, 'main provider window timing' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    allow(PWN::AI::Agent::TaskSummarizer).to receive(:enabled?).and_return(false)
    allow(PWN::AI::Agent::Registry).to receive(:discover)
    allow(PWN::AI::Agent::Registry).to receive(:definitions).and_return([])
    allow(described_class).to receive(:finish_debug_request!)
    allow(described_class).to receive(:debug_progress)
    @clock = 100.0
    allow(Process).to receive(:clock_gettime).and_call_original
    allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC) { @clock }
    allow(described_class).to receive(:repair_tool_history!) { @clock += 9 }
  end

  def run_turn(steering: nil)
    described_class.send(:run_turn, request: 'Return a fixture answer.', engine: :openai, system_role_content: 'fixture',
                                    enabled_toolsets: [], steering: steering, force_tools: true)
  end

  it 'charges an interrupted steering window before propagating the original interrupt' do
    steering = instance_double(PWN::AI::Agent::Loop::Steering, checkpoint: nil)
    error = Interrupt.new('synthetic exception payload')
    allow(steering).to receive(:model) do
      @clock += 33
      raise error
    end
    expect(described_class).not_to receive(:call_engine)
    expect { run_turn(steering: steering) }.to raise_error(Interrupt) { |raised| expect(raised).to equal(error) }
    expect(described_class).to have_received(:finish_debug_request!).with(hash_including(engine_s: 33.0))
    expect(described_class).to have_received(:debug_progress).with(msg: 'provider hop elapsed_s=33.0 exit=unwind')
  end

  it 'does not replace a non-local exit with a diagnostic sink failure' do
    allow(described_class).to receive(:call_engine) do
      @clock += 3
      throw :provider_exit, :original
    end
    allow(described_class).to receive(:debug_progress).with(msg: 'provider hop elapsed_s=3.0 exit=unwind').and_raise(IOError, 'fixture sink closed')
    expect { run_turn }.to throw_symbol(:provider_exit, :original)
    expect(described_class).to have_received(:finish_debug_request!).with(hash_including(engine_s: 3.0))
  end

  it 'adds a transient failure and a normal nil return, excluding time between hops' do
    attempts = 0
    allow(described_class).to receive(:call_engine) do
      @clock += 2.5
      attempts += 1
      raise IOError, 'HTTP 503 synthetic exception payload' if attempts == 1
    end
    expect(run_turn).to eq('[pwn-ai] engine returned no message')
    expect(attempts).to eq(2)
    expect(described_class).to have_received(:finish_debug_request!).with(hash_including(engine_s: 5.0))
    expect(described_class).to have_received(:debug_progress).with(msg: 'provider hop elapsed_s=2.5 exit=unwind')
    expect(described_class).to have_received(:debug_progress).with(msg: 'provider hop elapsed_s=2.5 exit=returned')
    expect(described_class).not_to have_received(:debug_progress).with(hash_including(msg: /synthetic exception payload/))
  end
end
