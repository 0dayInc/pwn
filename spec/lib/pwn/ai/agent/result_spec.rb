# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Result do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Result
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Result
    expect(help_response).to respond_to :help
  end

  it 'uses LOCAL_DEFAULT_MAX when active engine is ollama (0.3)' do
    allow(PWN::Env).to receive(:dig).and_call_original
    allow(PWN::Env).to receive(:dig).with(:ai, :active).and_return('ollama')
    allow(PWN::Env).to receive(:dig).with(:ai, :ollama, :result_max).and_return(nil)
    expect(described_class.default_max).to eq described_class::LOCAL_DEFAULT_MAX
    big = 'x' * 10_000
    out = described_class.condition(content: big)
    expect(out.length).to be < 10_000
    expect(out).to include('truncated')
  end
end
