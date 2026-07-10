# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # DECT (ETSI EN 300 175) true-air decoder.
      #
      # 1.152 Mbit/s GFSK, 24-slot / 10 ms TDMA. I/Q → PWN::FFI::Liquid
      # gmskdem (or DSP.fm_demod_iq→NRZ) → hunt 32-bit S-field
      # (16-bit preamble + 16-bit sync 0xE98A FP / 0x1675 PP) → A-field
      # (64 bits: 8-bit header + 40-bit tail + 16-bit R-CRC) → RFPI
      # extraction on Nt/Qt tails. Emits {rfpi:, role:, slot_est:, crc_ok:}.
      module DECT
        SYNC_FP = 0xAAAAE98A
        SYNC_PP = 0x55551675
        BAUD    = 1_152_000
        # R-CRC-16 poly x^16+x^10+x^8+x^7+x^3+1 = 0x0589, init 0x0000.
        RCRC_POLY = 0x0589
        A_TA = { 0 => 'Ct', 1 => 'Ct', 2 => 'Nt', 3 => 'Nt', 4 => 'Qt', 5 => 'Nt', 6 => 'Mt', 7 => 'Pt' }.freeze

        # Streaming DECT GFSK demod for Base.run_iq — I/Q → RFPI/A-field.
        class DemodIQ
          def initialize(rate:, carrier: nil)
            @rate    = rate.to_f
            @carrier = carrier
            @bits    = []
            @seen    = {}
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            [false, true].each do |inv|
              nb = PWN::SDR::Decoder::DSP.gfsk_slice(
                iq: samples, rate: @rate, baud: BAUD, bt: 0.5, invert: inv
              )
              scan(nb, inv, &) if block_given?
            end
          end

          private

          def scan(bits, inv)
            @bits.concat(bits)
            fp = Array.new(32) { |i| (SYNC_FP >> (31 - i)) & 1 }
            pp = Array.new(32) { |i| (SYNC_PP >> (31 - i)) & 1 }
            i = 0
            while i <= @bits.length - (32 + 64)
              role = nil
              role = 'FP' if err(@bits, i, fp) <= 3
              role ||= 'PP' if err(@bits, i, pp) <= 3
              if role
                a = @bits[i + 32, 64]
                hdr  = PWN::SDR::Decoder::DSP.bits_to_int(bits: a[0, 8])
                tail = a[8, 40]
                rcrc = PWN::SDR::Decoder::DSP.bits_to_int(bits: a[48, 16])
                bytes = PWN::SDR::Decoder::DSP.bytes_from_bits(bits: a[0, 48])
                calc  = PWN::SDR::Decoder::DSP.crc16(bytes: bytes, poly: RCRC_POLY, init: 0x0000)
                # DECT R-CRC XORs the final register with 0x0001
                crc_ok = ((calc ^ 0x0001) & 0xFFFF) == rcrc
                ta = (hdr >> 5) & 0x7
                rfpi = A_TA[ta] == 'Nt' ? tail[0, 40] : nil
                rfpi_hex = rfpi ? format('%010X', PWN::SDR::Decoder::DSP.bits_to_int(bits: rfpi)) : nil
                key = "#{role}:#{rfpi_hex}:#{format('%02X', hdr)}"
                unless @seen[key] && crc_ok
                  @seen[key] = true if crc_ok
                  @seen.shift if @seen.length > 128
                  yield(
                    protocol: 'DECT', event: 'a_field', role: role,
                    modulation: 'GFSK', header: format('%02X', hdr),
                    ta: ta, ta_name: A_TA[ta], rfpi: rfpi_hex,
                    tail_hex: format('%010X', PWN::SDR::Decoder::DSP.bits_to_int(bits: tail)),
                    rcrc: format('%04X', rcrc), crc_ok: crc_ok,
                    carrier: @carrier, polarity_inverted: inv,
                    summary: "DECT #{role} TA=#{A_TA[ta]}#{" RFPI=#{rfpi_hex}" if rfpi_hex} R-CRC=#{crc_ok ? 'OK' : 'BAD'}"
                  )
                end
                i += 32 + 64 + 320 # skip past B-field
              else
                i += 1
              end
            end
            @bits.shift([i - 32, 0].max) if i > 32
            @bits.shift(@bits.length - 8192) if @bits.length > 65_536
          end

          def err(bits, idx, pat)
            e = 0
            j = 0
            while j < pat.length
              e += 1 if bits[idx + j] != pat[j]
              return 99 if e > 3

              j += 1
            end
            e
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::DECT.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          hz = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          # EU: carrier 0 = 1897.344 MHz, step 1.728 MHz down; US 1.9296 GHz.
          carrier = ((1_897_344_000 - hz) / 1_728_000.0).round
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_304_000).to_i
          PWN::SDR::Decoder::Base.run_iq(
            freq_obj: freq_obj,
            protocol: 'DECT',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate, carrier: carrier),
            note: '1.152 Mbit/s GFSK — I/Q→gmskdem→S-field 0xE98A→A-field/RFPI/R-CRC.',
            describe: proc { |b| { modulation: 'GFSK', tdma_slots: (b[:duration_ms] / 0.417).round } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'DECT' }
          out[:rfpi]    = ::Regexp.last_match(1).delete(' ') if line =~ /RFPI[:=]?\s*((?:[0-9A-Fa-f]{2}\s*){5})/
          out[:slot]    = ::Regexp.last_match(1) if line =~ /slot\s*(\d+)/i
          out[:carrier] = ::Regexp.last_match(1) if line =~ /carrier\s*(\d+)/i
          out[:rssi]    = ::Regexp.last_match(1) if line =~ /RSSI[:=]?\s*(-?\d+)/i
          out[:role]    = ::Regexp.last_match(1) if line =~ /\b(FP|PP)\b/
          out[:summary] = "DECT RFPI=#{out[:rfpi]} slot=#{out[:slot]} carrier=#{out[:carrier]}"
          out.compact
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE (true-air I/Q via PWN::FFI + detector fallback):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq',
              source:   'optional - :auto|:rtlsdr|:adalm_pluto|:file',
              file:     'optional - .cu8/.cs16 capture (≥2.304 Msps)'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
