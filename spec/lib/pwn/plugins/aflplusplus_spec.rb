# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::AFLplusplus do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'parses execs_per_sec from a fuzzer_stats file' do
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, 'fuzzer_stats'), "execs_per_sec        : 1234.5\npaths_total          : 9\nunique_crashes       : 2\n")
      stats = described_class.parse_stats(out_dir: dir)
      expect(stats[:execs_per_sec] || stats['execs_per_sec']).to eq('1234.5')
    end
  end
end
