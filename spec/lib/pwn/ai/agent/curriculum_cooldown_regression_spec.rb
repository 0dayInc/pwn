# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Curriculum, 'persisted cooldown' do
  include_context 'pwn tmp sandbox'

  it 'does not self-play a signature already parked in the JSON cooldown ledger' do
    FileUtils.mkdir_p(described_class::CURRICULUM_DIR)
    stub_const('PWN::AI::Agent::Curriculum::COOLDOWN_FILE', File.join(described_class::CURRICULUM_DIR, 'cooldown.json'))
    stub_const('PWN::AI::Agent::Curriculum::KPI_FILE', File.join(@tmp, 'kpi.jsonl'))
    File.write(described_class::COOLDOWN_FILE, JSON.generate('fixture' => { fail_nights: 3, parked: true }))
    allow(PWN::AI::Agent::Mistakes).to receive(:top).and_return([{ signature: 'fixture', tool: 'shell', count: 4 }])
    expect(described_class).not_to receive(:self_play)
    allow(described_class).to receive(:generate_reproducers).and_return(['offline fixture'])
    result = described_class.practice(limit: 1, dry_run: true)
    expect(result).to include(practiced: 0, skipped_cooldown: 1)
  end
end
