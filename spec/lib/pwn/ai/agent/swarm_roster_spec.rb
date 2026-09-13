# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::AI::Agent::Swarm, 'specialist roster' do
  before do
    @swarm_home = Dir.mktmpdir('pwn-swarm-roster')
    allow(Dir).to receive(:home).and_return(@swarm_home)
    stub_const('PWN::AI::Agent::Swarm::AGENTS_FILE', File.join(@swarm_home, 'agents.yml'))
    stub_const('PWN::AI::Agent::Swarm::SWARM_ROOT', File.join(@swarm_home, 'swarm'))
  end

  after { FileUtils.remove_entry(@swarm_home) }

  it 'packs a lead roster of recon authz injection xss and business_logic specialists' do
    roster = described_class.ensure_specialists(swarm_id: 'fixture-swarm')
    expect(roster.map { |row| row[:name] }).to eq(%w[recon authz injection xss business_logic])
    roster.each do |row|
      expect(row[:ephemeral]).to eq(true)
      expect(row[:persona][:skills].length).to be <= 3
      expect(row[:persona][:toolsets]).not_to include('swarm')
      expect(row[:persona][:toolsets]).to include('pwn', 'http')
    end
    graph = described_class.view_graph(swarm_id: 'fixture-swarm')
    expect(graph[:agents]).to eq([])
    expect(described_class.specialist_roles.keys).to include(:recon, :authz, :injection, :xss, :business_logic)
  end
end
