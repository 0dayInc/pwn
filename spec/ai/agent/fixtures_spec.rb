# frozen_string_literal: true

require 'spec_helper'
require 'json'

describe 'spec/ai/agent fixtures' do
  it 'REQ-09 taxonomy goldens stay distinct' do
    rows = JSON.parse(File.read(File.join(__dir__, 'fixtures', 'req09_docker.json')))['req09']
    classes = rows.map { |r| PWN::AI::Agent::Mistakes.error_class(error: r['error']) }
    expect(classes).to eq(rows.map { |r| r['class'] })
    expect(classes.uniq.length).to eq(3)
  end
end
