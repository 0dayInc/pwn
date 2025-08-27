# frozen_string_literal: true

require 'barby'
require 'base64'
require 'fileutils'
require 'chunky_png'
require 'rqrcode'

module PWN
  module Plugins
    # This plugin is used to Create Scannable BarCodes and QR Codes
    module ScannableCodes
      # Supported Method Parameters::
      # response = PWN::Plugins::ScannableCodes.generate(
      #   data: 'required - data to encode',
      #   type: 'optional - :barcode || :qrcode (defaults to :qrcode)',
      #   size: 'optional - size of the image when type is :qrcode (defaults to 200)',
      #   path: 'optional - path to save image (defaults to "./#{data}.png")'
      #   return_type: 'optional - :base64 || :file (defaults to :file)'
      # )

      public_class_method def self.generate(opts = {})
        data = opts[:data]
        raise 'ERROR: option data is required.' unless data

        type = opts[:type]
        type ||= :qrcode

        size = opts[:size]
        raise 'ERROR: size is only applicable when type is :qrcode.' if size && type != :qrcode

        path = opts[:path]
        path ||= "./#{data}.png"

        return_type = opts[:return_type] ||= :file

        case type
        when :barcode
          barcode = Barby::Code128B.new(data)
          barcode.to_png.save(path)
        when :qrcode
          size ||= 200
          qrcode = RQRCode::QRCode.new(data)
          png = qrcode.as_png
          png.resize(size, size).save(path)
        else
          raise 'ERROR: type must be :barcode or :qrcode.'
        end

        data = "Saved #{type} to #{path}"
        if return_type == :base64
          data = Base64.strict_encode64(File.binread(path))
          FileUtils.rm_f(path)
        end

        data
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
            size: 'optional - size of the image when type is :qrcode (defaults to 200)',
            path: 'optional - path to save image (defaults to \"./\#{data}.png\")'
          )

          #{self}.authors
        "
      end
    end
  end
end
