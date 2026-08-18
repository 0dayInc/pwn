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

  it 'DEFAULT_PREFERENCE names only CORE_TOOLS in a recall-first fallback' do
    expect(described_class::DEFAULT_PREFERENCE).to eq(
      %w[memory_recall pwn_eval shell mistakes_record mistakes_resolve learning_note_outcome memory_remember]
    )
    expect(described_class::DEFAULT_PREFERENCE - described_class::CORE_TOOLS).to be_empty
    expect(described_class::DEFAULT_PREFERENCE).not_to include('sessions_view')
  end

  it 'preference_order defaults to shell / pwn_eval — there is no request type' do
    expect(described_class.preference_order.first(2)).to eq(%w[shell pwn_eval])
    expect(described_class.preference_order(kind: :question).first(2)).to eq(%w[shell pwn_eval])
  end

  it 'preference_order still honors explicit empty list and Env override' do
    expect(described_class.preference_order(order: [])).to eq([])
    expect(described_class.preference_order(preference: %w[shell])).to eq(%w[shell])
  end

  it 'definitions(core_only: true) ships CORE_TOOLS, not the full ~85 schema set' do
    described_class.discover
    names = described_class.definitions(core_only: true).map { |t| t.dig(:function, :name) }
    expect(names).to match_array(described_class::CORE_TOOLS)
    expect(names).not_to include('sessions_view')
    expect(names.length).to be <= described_class::CORE_TOOLS.length
  end
end
