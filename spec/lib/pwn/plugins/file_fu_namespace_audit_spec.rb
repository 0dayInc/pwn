# frozen_string_literal: true

require 'spec_helper'
require 'tempfile'

RSpec.describe PWN::Plugins::FileFu, 'namespace audit regressions' do
  [3, 4].each do |length|
    it "truncates the file when removing #{length} bytes from a three-byte file" do
      Tempfile.create('file-fu-audit') do |file|
        file.write('abc')
        file.flush
        described_class.shift_file_up(path: file.path, bytes: length)
        expect(File.binread(file.path)).to eq('')
      end
    end
  end
end
