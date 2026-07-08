# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby LTE / UMTS / CDMA cellular activity detector.
      #
      # 1.4–20 MHz OFDMA/WCDMA is far beyond a 48 kHz audio tap and beyond
      # interpreted Ruby's real-time I/Q throughput. Native mode reports
      # channel occupancy / power only. `parse_line` retained for offline
      # cell_search / CellSearch text analysis.
      module LTE
        # Supported Method Parameters::
        # PWN::SDR::Decoder::LTE.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          PWN::SDR::Decoder::Base.run_detector(
            freq_obj: freq_obj,
            protocol: 'LTE',
            note: 'OFDMA (1.4–20 MHz, 15 kHz subcarriers) — native mode reports channel occupancy only.',
            threshold: 4.0,
            describe: proc { |_b| { modulation: 'OFDMA', subcarrier_khz: 15 } }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::LTE.parse_line(line: 'Found CELL ... PCI: 123 ...')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'LTE' }
          out[:earfcn] = ::Regexp.last_match(1) if line =~ /EARFCN[:= ]+(\d+)/i
          out[:pci]    = ::Regexp.last_match(1) if line =~ /(?:PCI|N_id_cell|Id)[:= ]+(\d{1,3})/i
          out[:prb]    = (::Regexp.last_match(1) || ::Regexp.last_match(2)) if line =~ /(?:PRB[:= ]+(\d+)|(\d+)\s*PRB)/i
          out[:cp]     = ::Regexp.last_match(1) if line =~ /\b(Normal|Extended)\b\s*CP/i
          out[:rsrp]   = ::Regexp.last_match(1) if line =~ /(-?\d+(?:\.\d+)?)\s*dBm/
          out[:freq_mhz] = ::Regexp.last_match(1) if line =~ /(\d{3,4}\.\d)\s*MHz/
          out[:summary] = "LTE PCI=#{out[:pci]} EARFCN=#{out[:earfcn]} PRB=#{out[:prb]} RSRP=#{out[:rsrp]}dBm"
          out.compact
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE (ruby-native detector, no external binaries):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            #{self}.parse_line(line: 'Found CELL 739.0 MHz, EARFCN=5110, PCI=123, 50 PRB, -85.2 dBm')

            #{self}.authors
          "
        end
      end
    end
  end
end
