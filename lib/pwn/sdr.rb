# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads SDR modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module SDR
    autoload :Decoder, 'pwn/sdr/decoder'
    autoload :FlipperZero, 'pwn/sdr/flipper_zero'
    autoload :FrequencyAllocation, 'pwn/sdr/frequency_allocation'
    autoload :GQRX, 'pwn/sdr/gqrx'
    autoload :RFIDler, 'pwn/sdr/rfidler'
    autoload :SonMicroRFID, 'pwn/sdr/son_micro_rfid'

    # Supported Method Parameters::
    # PWN::SDR.hz_to_s(
    #   freq: 'required - frequency in Hz (Integer or String)'
    # )
    public_class_method def self.hz_to_s(opts = {})
      freq = opts[:freq]
      str_hz = freq.to_s
      # Nuke leading zeros
      # E.g., 002450000000 -> 2450000000
      str_hz = str_hz.sub(/^0+/, '') unless str_hz == '0'
      # Insert dots every 3 digits from the right
      str_hz.reverse.scan(/.{1,3}/).join('.').reverse
    end

    # Supported Method Parameters::
    # PWN::SDR.hz_to_i(
    #   freq: 'required - frequency string (e.g. "2.450.000.000")'
    # )
    public_class_method def self.hz_to_i(opts = {})
      freq = opts[:freq]
      freq.to_s.gsub('.', '').to_i
    end

    # Display a List of Every PWN::AI Module

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      constants.sort
    end
  end
end
