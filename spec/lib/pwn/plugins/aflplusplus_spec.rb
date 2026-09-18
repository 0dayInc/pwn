# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'open3'
require 'fileutils'

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

  it 'builds an AFL dictionary from interesting binary strings' do
    Dir.mktmpdir('pwn-fuzz-dict-') do |dir|
      src = File.join(dir, 't.c')
      bin = File.join(dir, 't')
      File.write(src, "#include <stdio.h>\nint main(void) { puts(\"https://fuzz.example/token\"); return 0; }\n")
      out, status = Open3.capture2e('cc', '-O0', '-o', bin, src)
      expect(status.success?).to eq(true), out
      dict = described_class.dictionary_from_binary(path: bin)
      blob = Array(dict[:tokens] || dict).join("\n")
      expect(blob).to include('https://fuzz.example/token')
    end
  end

  it 'dedups crashes by backtrace hash and hands unique ones to RE triage' do
    Dir.mktmpdir('pwn-fuzz-dedup-') do |dir|
      crashes = File.join(dir, 'crashes')
      FileUtils.mkdir_p(crashes)
      File.binwrite(File.join(crashes, 'id:000000,sig:11'), 'AAAA')
      File.binwrite(File.join(crashes, 'id:000001,sig:11'), 'BBBB')
      File.binwrite(File.join(crashes, 'id:000002,sig:11'), 'CCCC')
      reports = {
        'AAAA' => { signal: 'SIGSEGV', pc: '0x401136', fault_addr: '0x401136', backtrace: [{ func: 'vuln' }] },
        'BBBB' => { signal: 'SIGSEGV', pc: '0x401136', fault_addr: '0x401136', backtrace: [{ func: 'vuln' }] },
        'CCCC' => { signal: 'SIGABRT', pc: '0x401200', fault_addr: '0x0', backtrace: [{ func: 'abort' }] }
      }
      allow(PWN::Plugins::GDBMI).to receive(:run_to_crash) do |opts|
        reports.fetch(opts[:stdin].to_s)
      end
      allow(PWN::Plugins::BinaryParser).to receive(:triage).and_return(file_type: 'elf', protections: { nx: true })
      allow(PWN::Plugins::ExploitDev).to receive(:from_crash).and_return(offset: 64)
      row = described_class.crash_triage(out_dir: dir, target: '/bin/true', handoff: true)
      expect(row[:unique].length).to eq(2)
      expect(row[:triaged].length).to eq(2)
      expect(row[:triaged]).to all(include(:backtrace_hash, :crash, :binary_triage))
      expect(row[:pipeline]).to eq('pwn-re-003')
    end
  end
end
