# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads SDR modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module SDR
    # Decoder namespace for SDR signals. Every child module exposes a
    # uniform `.decode(freq_obj:)` entry point (see PWN::SDR::Decoder::Base)
    # so PWN::SDR::GQRX can dispatch on a `decoder:` key from
    # PWN::SDR::FrequencyAllocation.band_plans.
    #
    # 100 % ruby-native — no decoder in this namespace shells out to an
    # external binary. Three pipelines (Base):
    #   run_native   — GQRX 48 kHz audio tap (POCSAG/FLEX/Morse/RTTY/APT/Pager)
    #   run_iq       — true-air I/Q via PWN::FFI::{RTLSdr,AdalmPluto,HackRF}
    #                  or a .cu8/.cs16 capture file; all modules use this when
    #                  hardware/file is present (ADS-B fully slices Mode-S PPM)
    #   run_detector — energy/burst characterizer fallback when no I/Q source
    module Decoder
      autoload :ADSB,      'pwn/sdr/decoder/adsb'
      autoload :APT,       'pwn/sdr/decoder/apt'
      autoload :Base,      'pwn/sdr/decoder/base'
      autoload :Bluetooth, 'pwn/sdr/decoder/bluetooth'
      autoload :DECT,      'pwn/sdr/decoder/dect'
      autoload :DSP,       'pwn/sdr/decoder/dsp'
      autoload :Flex,      'pwn/sdr/decoder/flex'
      autoload :GPS,       'pwn/sdr/decoder/gps'
      autoload :GSM,       'pwn/sdr/decoder/gsm'
      autoload :Iridium,   'pwn/sdr/decoder/iridium'
      autoload :LTE,       'pwn/sdr/decoder/lte'
      autoload :LoRa,      'pwn/sdr/decoder/lora'
      autoload :Morse,     'pwn/sdr/decoder/morse'
      autoload :P25,       'pwn/sdr/decoder/p25'
      autoload :POCSAG,    'pwn/sdr/decoder/pocsag'
      autoload :Pager,     'pwn/sdr/decoder/pager'
      autoload :RDS,       'pwn/sdr/decoder/rds'
      autoload :RFID,      'pwn/sdr/decoder/rfid'
      autoload :RTL433,    'pwn/sdr/decoder/rtl433'
      autoload :RTTY,      'pwn/sdr/decoder/rtty'
      autoload :WiFi,      'pwn/sdr/decoder/wifi'
      autoload :ZigBee,    'pwn/sdr/decoder/zigbee'

      # symbol → module map. Keys are what a band_plan's :decoder value (or
      # PWN::SDR::GQRX.init_freq's decoder: kwarg) may be set to.
      REGISTRY = {
        adsb: :ADSB,
        apt: :APT,
        bluetooth: :Bluetooth,
        dect: :DECT,
        flex: :Flex,
        gprs: :GSM,
        gps: :GPS,
        gsm: :GSM,
        iridium: :Iridium,
        ism: :RTL433,
        keyfob: :RTL433,
        lora: :LoRa,
        lte: :LTE,
        morse: :Morse,
        p25: :P25,
        pager: :Pager,
        pocsag: :POCSAG,
        rds: :RDS,
        rfid: :RFID,
        rtl433: :RTL433,
        rtty: :RTTY,
        wifi: :WiFi,
        zigbee: :ZigBee
      }.freeze

      # Supported Method Parameters::
      # mod = PWN::SDR::Decoder.resolve(
      #   decoder: 'required - Symbol/String key from REGISTRY (e.g. :pocsag)'
      # )

      public_class_method def self.resolve(opts = {})
        key = opts[:decoder].to_s.downcase.to_sym
        const = REGISTRY[key]
        raise "ERROR: Unknown decoder key #{key.inspect}. Supported: #{REGISTRY.keys.sort.join(', ')}" unless const

        const_get(const)
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      # Display a List of Every PWN::SDR::Decoder Module

      public_class_method def self.help
        constants.sort
      end
    end
  end
end
