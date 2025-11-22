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

    # Display a List of Every PWN::AI Module

    public_class_method def self.help
      constants.sort
    end
  end
end
