# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Registry do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Registry
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Registry
    expect(help_response).to respond_to :help
  end

  it 'CORE_TOOLS is recall-then-act including skills_recall before pwn_eval' do
    expect(described_class.const_defined?(:ACT_PREFERENCE)).to eq false
    expect(described_class::CORE_TOOLS).to eq(
      %w[memory_recall session_recall skills_recall pwn_eval shell mistakes_record mistakes_resolve learning_note_outcome memory_remember skills_update]
    )
    expect(described_class::DEFAULT_PREFERENCE).to eq(described_class::CORE_TOOLS)
    expect(described_class::DEFAULT_PREFERENCE).not_to include('sessions_view')
    expect(described_class::CORE_TOOLS.index('memory_recall')).to be < described_class::CORE_TOOLS.index('session_recall')
    expect(described_class::CORE_TOOLS.index('session_recall')).to be < described_class::CORE_TOOLS.index('skills_recall')
    expect(described_class::CORE_TOOLS.index('skills_recall')).to be < described_class::CORE_TOOLS.index('pwn_eval')
    expect(described_class::CORE_TOOLS.index('pwn_eval')).to be < described_class::CORE_TOOLS.index('shell')
  end

  it 'preference_order is DEFAULT_PREFERENCE — kind/intent do not change it' do
    expect(described_class.preference_order).to eq(described_class::DEFAULT_PREFERENCE)
    expect(described_class.preference_order.first(5)).to eq(%w[memory_recall session_recall skills_recall pwn_eval shell])
    expect(described_class.preference_order(kind: :question)).to eq(described_class::DEFAULT_PREFERENCE)
    expect(described_class.preference_order(intent: :recall)).to eq(described_class::DEFAULT_PREFERENCE)
  end

  it 'preference_order still honors explicit empty list and Env override' do
    expect(described_class.preference_order(order: [])).to eq([])
    expect(described_class.preference_order(preference: %w[shell])).to eq(%w[shell])
  end

  it 'definitions(core_only: true) ships CORE_TOOLS, not the full ~85 schema set' do
    described_class.discover
    names = described_class.definitions(core_only: true).map { |t| t.dig(:function, :name) }
    expect(names).to eq(described_class::CORE_TOOLS)
    expect(names).not_to include('sessions_view')
    expect(names.length).to eq(described_class::CORE_TOOLS.length)
  end
end
