# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'

describe PWN::Engagement do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'persists host state and requires override for out-of-scope targets' do
    Dir.mktmpdir('eng') do |dir|
      stub_const('PWN::AI::Agent::Engagement::ROOT', dir)
      stub_const('PWN::AI::Agent::Engagement::ACTIVE_FILE', File.join(dir, 'active'))
      described_class.open(name: 'lab', scope_cidrs: ['10.0.0.0/8'])
      described_class.record_host(host: '10.1.2.3', ports: [22], notes: ['ssh'])
      expect(described_class.hosts.values.first[:ports]).to include(22)
      expect(described_class.warn_unless_in_scope(host: '8.8.8.8')[:override_required]).to eq(true)
      described_class.record_host(host: '8.8.8.8', ports: [53], override: true)
      expect(described_class.hosts.values.map { |row| row[:host] }).to include('8.8.8.8')
    end
  end
end
