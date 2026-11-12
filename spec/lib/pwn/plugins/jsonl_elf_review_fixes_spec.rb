# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'tmpdir'

RSpec.describe 'JSONL rejection and ELF32 dynamic symbols' do
  it '[PBR-07] reports malformed JSONL instead of an empty successful scan' do
    Dir.mktmpdir('jsonl-review-') do |dir|
      missing = File.join(dir, 'absent.jsonl')
      expect(PWN::Plugins::Httpx.probe(jsonl: missing)[:error]).to eq('missing jsonl file')
      expect(PWN::Plugins::Nuclei.scan(jsonl: missing, record: false)[:error]).to eq('missing jsonl file')

      bad = File.join(dir, 'bad.jsonl')
      File.write(bad, "not-json\n")
      malformed = PWN::Plugins::Httpx.probe(jsonl: bad)
      expect(malformed[:hosts]).to eq([])
      expect(malformed[:rejected]).to eq(1)

      mixed = File.join(dir, 'mixed.jsonl')
      File.write(mixed, "#{JSON.generate('url' => 'https://kept.example')}\nnot-json\n\n")
      kept = PWN::Plugins::Httpx.probe(jsonl: mixed)
      expect(kept[:hosts].map { |row| row['url'] }).to eq(['https://kept.example'])
      expect(kept[:rejected]).to eq(1)

      nuclei = PWN::Plugins::Nuclei.scan(jsonl: bad, record: false)
      expect(nuclei[:findings]).to eq([])
      expect(nuclei[:rejected]).to eq(1)
    end
  end

  it '[PBR-09] does not use DT_STRSZ as the dynamic symbol-table size' do
    Dir.mktmpdir('elf32-review-') do |dir|
      path = File.join(dir, 'rel32')
      base = 0x8048000
      dynamic_offset = 0x100
      symbol_offset = 0x200
      string_offset = 0x240
      rel_offset = 0x280
      dyn = [[5, base + string_offset], [6, base + symbol_offset], [10, 8], [11, 16],
             [23, base + rel_offset], [2, 8], [20, 17], [0, 0]].map { |row| row.pack('V2') }.join
      data = "\0".b * 0x300
      data[0, 16] = "\x7fELF\x01\x01\x01".b.ljust(16, "\0")
      data[16, 36] = [2, 3, 1, base, 52, 0, 0, 52, 32, 2, 40, 0, 0].pack('vvVVVVVvvvvvv')
      data[52, 32] = [1, 0, base, base, data.bytesize, data.bytesize, 5, 4096].pack('V8')
      data[84, 32] = [2, dynamic_offset, base + dynamic_offset, base + dynamic_offset, dyn.bytesize, dyn.bytesize, 6, 4].pack('V8')
      data[dynamic_offset, dyn.bytesize] = dyn
      data[symbol_offset + 16, 16] = [1, 0, 0, 0x12, 0, 0].pack('VVVCCv')
      data[string_offset, 8] = "\0system\0".b
      data[rel_offset, 8] = [base + 0x2c0, (1 << 8) | 7].pack('V2')
      File.binwrite(path, data)

      row = PWN::Plugins::BinaryParser.elf_resolve(path: path)
      expect(row[:arch]).to eq('i386')
      expect(row[:got]['system']).to eq(base + 0x2c0)
      expect(row[:symbols]['system']).not_to be_nil
    end
  end
end
