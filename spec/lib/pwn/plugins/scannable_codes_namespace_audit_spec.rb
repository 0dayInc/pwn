# frozen_string_literal: true

require 'spec_helper'
require 'tempfile'

RSpec.describe PWN::Plugins::ScannableCodes, 'barcode regression' do
  it 'renders a Code128 barcode as a PNG file' do
    Tempfile.create(['barcode-audit', '.png']) do |file|
      described_class.generate(data: 'offline fixture', type: :barcode, path: file.path)
      png = ChunkyPNG::Image.from_file(file.path)
      expect(png.width).to be_positive
      expect(png.height).to be_positive
    end
  end
end
