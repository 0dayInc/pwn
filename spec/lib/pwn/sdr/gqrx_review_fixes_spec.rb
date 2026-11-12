# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::SDR::GQRX, 'review configuration insertion regressions' do
  ["[input]\n[output]\nsample_rate=333\n", "[input]\n\n[output]\nsample_rate=333\n",
   "[input]\r\n[output]\r\nsample_rate=333\r\n", '[input]'].each do |original|
    it "PSR-L02 inserts a distinct sample-rate line in #{original.inspect}" do
      Dir.mktmpdir('gqrx-empty-input') do |dir|
        file = File.join(dir, 'fixture.conf')
        File.binwrite(file, original)
        result = described_class.set_input_rate(path: file, input_rate: 24_000, clamp: false, restart: false)
        expect(result).to include(input_rate: 24_000, restarted: false)
        lines = File.readlines(file, chomp: true)
        expect(lines.first(2)).to eq(['[input]', 'sample_rate=24000'])
        expect(lines.drop(2)).to eq(original.lines(chomp: true).drop(1))
        expect(described_class.read_input_config(path: file)[:input_rate]).to eq(24_000)
      end
    end
  end
end
