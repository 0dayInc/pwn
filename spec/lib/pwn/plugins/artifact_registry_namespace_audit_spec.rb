# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::ArtifactRegistry, 'session path regression' do
  it 'rejects traversal session identifiers before registering a file' do
    Dir.mktmpdir('artifact-audit') do |dir|
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
      source = File.join(dir, 'source.bin')
      File.binwrite(source, 'fixture')
      expect { described_class.register(session_id: '../outside', path: source) }.to raise_error(ArgumentError, /session_id/)
      expect(File.exist?(File.join(dir, 'outside', 'source.bin'))).to be(false)
    end
  end

  it 'rejects traversal session identifiers before listing an index' do
    expect { described_class.list(session_id: '../outside') }.to raise_error(ArgumentError, /session_id/)
  end
end
