# frozen_string_literal: true

require 'spec_helper'

describe 'PWN::AI::Agent::Tools sbom_scan' do
  it 'registers sbom_scan' do
    load '/opt/pwn/lib/pwn/ai/agent/tools/sbom_scan.rb'
    expect(PWN::AI::Agent::Registry.lookup(name: 'sbom_scan')).not_to be_nil
  end
end
