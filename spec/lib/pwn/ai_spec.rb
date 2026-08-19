# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI do
  it 'should return data for help method' do
    help_response = PWN::AI.help
    expect(help_response).not_to be_nil
  end

  it 'does not expose plan-usage helpers' do
    expect(described_class).not_to respond_to(:normalize_plan_usage)
    expect(described_class).not_to respond_to(:plan_usage)
    expect(described_class).not_to respond_to(:plan_usage_glyph)
  end
end
