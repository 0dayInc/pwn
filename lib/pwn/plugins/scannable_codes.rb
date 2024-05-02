# frozen_string_literal: true

require 'barby'
require 'rqrcode'
require 'chunky_png'

module PWN
  module Plugins
    # This plugin is used to Create Scannable BarCodes and QR Codes
    module ScannableCodes
      # Supported Method Parameters::
      # response = PWN::Plugins::ScannableCodes.generate(
      #   data: 'required - data to encode',
      #   type: 'optional - :barcode || :qrcode (defaults to :qrcode)',
      #   path: 'optional - path to save image (defaults to "./#{data}.png")'
      # )

      public_class_method def self.generate(opts = {})
        data = opts[:data]
        raise 'ERROR: option data is required.' unless data

        type = opts[:type]
        type ||= :qrcode

        path = opts[:path]
        path ||= "./#{data}.png"

        case type
        when :barcode
          barcode = Barby::Code128B.new(data)
          barcode.to_png.save(path)
        when :qrcode
          qrcode = RQRCode::QRCode.new(data)
          png = qrcode.as_png
          png.resize(200, 200).save(path)
        else
          raise 'ERROR: type must be :barcode or :qrcode.'
        end

        puts "Saved #{type} to #{path}"
      rescue Interrupt
        puts "\nGoodbye."
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.generate(
            data: 'required - data to encode',
            type: 'optional - :barcode || :qrcode (defaults to :qrcode)',
            path: 'optional - path to save image (defaults to \"./\#{data}.png\")'
          )

          #{self}.authors
        "
      end
    end
  end
end
