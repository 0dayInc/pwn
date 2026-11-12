# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'digest'

RSpec.describe PWN::AI::Context, 'byte range regressions' do
  { (0..0) => 'a', (1..3) => 'bcd', (1...3) => 'bc', (2...2) => '' }.each do |range, expected|
    it "persists precisely the bytes selected by #{range.inspect}" do
      Dir.mktmpdir('context-range-audit-') do |dir|
        allow(Dir).to receive(:home).and_return(dir)
        stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
        path = File.join(dir, 'source.txt')
        File.binwrite(path, 'abcdef')
        result = described_class.attach_file(path: path, range: range, session_id: 'fixture-range')
        expect(File.binread(result[:path])).to eq(expected)
        expect(result[:chunks].join).to eq(expected)
        expect(result[:size]).to eq(expected.bytesize)
        expect(result[:sha256]).to eq(Digest::SHA256.hexdigest(expected))
        expect(File.binread(path)).to eq('abcdef')
      end
    end
  end
end
