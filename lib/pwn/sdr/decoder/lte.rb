# frozen_string_literal: true

require 'shellwords'

module PWN
  module SDR
    module Decoder
      # LTE / UMTS / CDMA / PCS / AWS wideband cellular cell-search decoder.
      #
      # 1.4–20 MHz OFDMA/WCDMA cannot be recovered from GQRX audio; this
      # module drives srsRAN's `cell_search` (or `LTE-Cell-Scanner`'s
      # `CellSearch`) directly against the SDR to enumerate physical cells:
      # EARFCN, PCI, CP type, RSRP/RSRQ, PSS/SSS correlation.
      module LTE
        # Supported Method Parameters::
        # PWN::SDR::Decoder::LTE.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          hz       = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          gain     = (freq_obj[:rf_gain] || 40).to_s.to_f
          sdr_args = (freq_obj[:sdr_args] || 'driver=rtlsdr').to_s

          direct_cmd =
            if PWN::SDR::Decoder::Base.bin_available?(bin: 'cell_search')
              # srsRAN cell_search takes a band number; fall back to explicit
              # DL frequency via -s/-e range when unavailable.
              "cell_search -a #{Shellwords.escape(sdr_args)} -g #{gain} -s #{hz} -e #{hz}"
            else
              "CellSearch -s #{hz / 1_000_000.0} -e #{hz / 1_000_000.0} -g #{gain}"
            end

          PWN::SDR::Decoder::Base.run_pipeline(
            freq_obj: freq_obj,
            protocol: 'LTE',
            required_bins: %w[cell_search],
            direct_cmd: direct_cmd,
            line_match: /(CELL|PCI|EARFCN|Found|RSRP|CID)/i,
            parser: proc { |line| parse_line(line: line) }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::LTE.parse_line(line: 'Found CELL ... PCI: 123 ... PRB: 50 ... -85.0 dBm')

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
          puts "USAGE:
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            NOTE: Requires srsRAN `cell_search` (or LTE-Cell-Scanner
                  `CellSearch`). Owns the SDR — set freq_obj[:sdr_args].

            #{self}.parse_line(line: 'Found CELL 739.0 MHz, EARFCN=5110, PCI=123, 50 PRB, -85.2 dBm')

            #{self}.authors
          "
        end
      end
    end
  end
end
