# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Learning, 'pruning accounting' do
  include_context 'pwn tmp sandbox'

  it 'counts a duplicate only once in removed outcomes' do
    rows = 3.times.map do |index|
      { id: "fixture-#{index}", task: 'same task', success: false, details: '', timestamp: '2020-01-01T00:00:00Z' }
    end
    File.write(described_class::LEARNING_FILE, "#{rows.map { |row| JSON.generate(row) }.join("\n")}\n")
    result = described_class.prune_outcomes!
    expect(result).to include(kept: 1, removed: 2, deduped: 2)
    expect(described_class.outcomes.length).to eq(1)
  end
end
