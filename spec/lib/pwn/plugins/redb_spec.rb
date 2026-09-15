# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe PWN::Plugins::REDB do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'answers who calls strcpy from cache on a second open' do
    Dir.mktmpdir('redb') do |dir|
      stub_const('PWN::Plugins::REDB::ROOT', File.join(dir, 'redb'))
      src = File.join(dir, 'x.c')
      bin = File.join(dir, 'x')
      File.write(src, "#include <string.h>\nvoid caller(void){ char b[8]; strcpy(b, \"x\"); }\nint main(void){ caller(); return 0; }\n")
      system('cc', '-O0', '-g', '-fno-builtin', '-fno-inline', '-o', bin, src)
      described_class.open(bin: bin)
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      described_class.open(bin: bin)
      xrefs = described_class.xrefs_to(bin: bin, sym: 'strcpy')
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0
      expect(elapsed).to be < 1.0
      expect(xrefs).to be_an(Array)
      expect(xrefs.map { |row| row['dst'] || row[:dst] }).to include('strcpy')
    end
  end
end
