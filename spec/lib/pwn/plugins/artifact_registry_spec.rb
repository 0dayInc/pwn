# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::ArtifactRegistry do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'lists artifacts for a session id' do
    Dir.mktmpdir do |dir|
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', dir)
      src = File.join(dir, 'loot.txt')
      File.write(src, 'x')
      described_class.register(session_id: 'sess1', path: src, kind: 'loot')
      rows = described_class.list(session_id: 'sess1')
      expect(rows.first[:kind]).to eq('loot')
    end
  end
end
