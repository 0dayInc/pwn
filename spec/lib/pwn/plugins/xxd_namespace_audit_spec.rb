# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::XXD, 'partial-row reversal regression' do
  it 'preserves a partial final row when reversing into byte chunks' do
    Dir.mktmpdir('xxd-chunks-audit') do |dir|
      source = File.join(dir, 'input.bin')
      output = File.join(dir, 'output.bin')
      data = ('A B ' * 8).byteslice(0, 29)
      File.binwrite(source, data)
      dump = described_class.dump(file: source)
      described_class.reverse_dump(hexdump: dump, file: output, byte_chunks: 16)
      expect(File.binread("#{output}.00000010-00000010")).to eq(data.byteslice(16..))
    end
  end

  [13, 14, 15].each do |length|
    [false, true].each do |hashed|
      it "round-trips #{length} bytes with spaced ASCII and hashed=#{hashed}" do
        Dir.mktmpdir('xxd-audit') do |dir|
          source = File.join(dir, 'input.bin')
          output = File.join(dir, 'output.bin')
          data = ('A B ' * 4).byteslice(0, length)
          File.binwrite(source, data)
          dump = described_class.dump(file: source, hashed: hashed)
          described_class.reverse_dump(hexdump: dump, file: output)
          expect(File.binread(output)).to eq(data)
        end
      end
    end
  end
end
