# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # ADS-B (1090 MHz Mode-S / 978 MHz UAT) true-air decoder.
      #
      # Prefer PWN::FFI::{RTLSdr,AdalmPluto,HackRF} at ≥2 Msps and run a
      # pure-Ruby Mode-S preamble correlator + 112-bit PPM slicer over
      # magnitude samples. Falls back to Base.run_detector energy mode
      # when no I/Q source is available. Offline SBS-1 CSV → .parse_line.
      module ADSB
        SBS_FIELDS = %i[
          msg_type tx_type session_id aircraft_id icao24 flight_id
          date_gen time_gen date_log time_log callsign altitude_ft
          ground_speed_kt track_deg lat lon vertical_rate_fpm squawk
          alert emergency spi on_ground
        ].freeze

        # 8 μs Mode-S preamble at 2 Msps → 16 samples: 1 0 1 0 0 0 0 1 0 1 0 0 0 0 0 0
        PREAMBLE = [1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0].map(&:to_f).freeze
        SAMPLES_PER_US = 2 # @ 2 Msps
        # CRC-24 (Mode-S) generator 0x1FFF409  (poly over GF(2), 24-bit)
        MODE_S_CRC_POLY = 0x1FFF409

        # Streaming I/Q demod for Base.run_iq.
        class DemodIQ
          def initialize(rate: 2_000_000)
            @rate = rate.to_f
            @spb  = @rate / 1_000_000.0 # samples per µs (expect ~2)
            @mag  = []
            @seen = {}
          end

          def feed_iq(samples, rate: nil, &emit)
            @rate = rate.to_f if rate
            @spb  = @rate / 1_000_000.0
            m2 = PWN::SDR::Decoder::DSP.mag_sq(iq: samples)
            @mag.concat(m2)
            # Scan the entire buffer FIRST so frames that land earlier in a
            # multi-ms chunk are not discarded by the ring-buffer clamp below.
            # Only AFTER scan() has consumed what it can do we cap residual
            # history (frame + preamble headroom ≈ 0.5 ms, keep 50 ms).
            scan(&emit)
            max = (@rate * 0.05).to_i
            @mag.shift(@mag.length - max) if @mag.length > max
          end

          private

          def scan
            plen = PREAMBLE.length
            return if @mag.length < plen + (112 * 2)

            # Sliding correlator for the 4-pulse Mode-S preamble. Require the
            # on-pulse peaks to dominate the off-slots by a clear margin and
            # require DF ∈ known set before emitting (cuts noise catastrophically).
            i = 0
            accepted = 0
            while i < @mag.length - (plen + 224)
              # Pulse peaks at samples 0, 2, 7, 9; valleys at 1,3,4,5,6,8,10..
              p0 = @mag[i]
              p2 = @mag[i + 2]
              p7 = @mag[i + 7]
              p9 = @mag[i + 9]
              peak = (p0 + p2 + p7 + p9) / 4.0
              valley = (
                @mag[i + 1] + @mag[i + 3] + @mag[i + 4] + @mag[i + 5] +
                @mag[i + 6] + @mag[i + 8] + @mag[i + 10] + @mag[i + 12]
              ) / 8.0
              if peak > valley * 2.5 && peak.positive?
                bits = slice_ppm(@mag, i + plen, 112)
                if bits && bits.length == 112
                  df = PWN::SDR::Decoder::DSP.bits_to_int(bits: bits[0, 5])
                  # DF 0/4/5/11/16/17/18/20/21 are the Mode-S set we care about
                  if [0, 4, 5, 11, 16, 17, 18, 20, 21].include?(df)
                    # ICAO all-zeros / all-ones is almost always garbage
                    icao_bits = bits[8, 24]
                    icao_int = PWN::SDR::Decoder::DSP.bits_to_int(bits: icao_bits)
                    if icao_int.positive? && icao_int != 0xFFFFFF && ADSB.crc_ok?(bits: bits)
                      msg = ADSB.decode_modes(bits: bits)
                      key = "#{msg[:icao24]}:#{msg[:df]}:#{msg[:raw_hex].to_s[0, 8]}"
                      unless @seen[key]
                        @seen[key] = true
                        @seen.shift if @seen.length > 512
                        yield msg
                        accepted += 1
                      end
                      i += plen + 224
                      next
                    end
                  end
                end
              end
              i += 1
            end
            drop = [i - plen, 0].max
            @mag.shift(drop) if drop.positive?
            accepted
          end

          # Mode-S Pulse-Position Modulation: 1 µs = 2 samples; high-first → 1.
          def slice_ppm(mag, start, nbits)
            bits = Array.new(nbits)
            nbits.times do |b|
              a = start + (b * 2)
              return nil if a + 1 >= mag.length

              bits[b] = mag[a] >= mag[a + 1] ? 1 : 0
            end
            bits
          end
        end

        # Supported Method Parameters::
        # crc = PWN::SDR::Decoder::ADSB.crc24(bits: Array<0|1>)
        # CRC over all bits except the final 24 (which hold the parity).

        public_class_method def self.crc24(opts = {})
          bits = opts[:bits] || []
          return nil if bits.length < 32

          # Mode-S CRC-24: left-shift register fed by every message bit
          # (including the 24 parity bits). A valid frame leaves residual 0.
          reg = 0
          bits.each do |b|
            reg <<= 1
            reg |= (b & 1)
            reg ^= MODE_S_CRC_POLY if reg.anybits?(0x1000000)
          end
          reg & 0xFFFFFF
        end

        # Supported Method Parameters::
        # ok = PWN::SDR::Decoder::ADSB.crc_ok?(bits: Array<0|1>)

        public_class_method def self.crc_ok?(opts = {})
          bits = opts[:bits] || []
          return false unless [56, 112].include?(bits.length)

          crc24(bits: bits).zero?
        end

        # Supported Method Parameters::
        # h = PWN::SDR::Decoder::ADSB.decode_modes(bits: Array<0|1> of length 56 or 112)

        public_class_method def self.decode_modes(opts = {})
          bits = opts[:bits] || []
          return nil unless [56, 112].include?(bits.length)

          # DF (5) + CA (3) + ICAO (24) + ...
          df = PWN::SDR::Decoder::DSP.bits_to_int(bits: bits[0, 5])
          icao = format('%06X', PWN::SDR::Decoder::DSP.bits_to_int(bits: bits[8, 24]))
          out = {
            protocol: 'ADSB',
            df: df,
            icao24: icao,
            bits: bits.length,
            raw_hex: bits.each_slice(4).map { |n| PWN::SDR::Decoder::DSP.bits_to_int(bits: n).to_s(16) }.join.upcase
          }
          # DF17/18 ME field (56 bits starting at bit 32)
          if [17, 18].include?(df) && bits.length >= 88
            tc = PWN::SDR::Decoder::DSP.bits_to_int(bits: bits[32, 5])
            out[:type_code] = tc
            if tc.between?(1, 4)
              # aircraft identification — 8× 6-bit AIS chars
              cs = bits[40, 48].each_slice(6).map { |ch| ais_char(code: PWN::SDR::Decoder::DSP.bits_to_int(bits: ch)) }.join.strip
              out[:callsign] = cs
            elsif tc.between?(9, 18) || tc.between?(20, 22)
              out[:altitude_ft] = modes_altitude(bits12: bits[40, 12])
            end
          end
          bits_s = []
          bits_s << "ICAO=#{out[:icao24]}"
          bits_s << "DF=#{df}"
          bits_s << "CS=#{out[:callsign]}" if out[:callsign]
          bits_s << "ALT=#{out[:altitude_ft]}ft" if out[:altitude_ft]
          bits_s << "TC=#{out[:type_code]}" if out[:type_code]
          out[:summary] = "ADSB #{bits_s.join(' ')}"
          out
        end

        public_class_method def self.ais_char(opts = {})
          code = opts[:code]
          table = '#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######'
          table[code] || ' '
        end

        public_class_method def self.modes_altitude(opts = {})
          bits12 = opts[:bits12]
          return nil unless bits12.is_a?(Array) && bits12.length == 12

          # Gillham / 25 ft encoding — simplified (bit 7 is Q)
          q = bits12[7]
          if q == 1
            n = PWN::SDR::Decoder::DSP.bits_to_int(bits: bits12[0, 7] + bits12[8, 4])
            return (n * 25) - 1000
          end
          nil
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::ADSB.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          hz  = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          uat = hz.between?(977_000_000, 979_000_000)
          proto = uat ? 'ADSB-UAT978' : 'ADSB-1090ES'
          rate  = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_000_000).to_i
          PWN::SDR::Decoder::Base.run_iq(
            freq_obj: freq_obj,
            protocol: proto,
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate),
            note: 'Mode-S 2 Mbit/s PPM — true-air path uses RTL-SDR/Pluto I/Q; detector fallback characterises squitter density only.',
            describe: proc { |b| { modulation: 'PPM', frame_len_us: 120, classification: b[:duration_ms] < 5 ? 'squitter' : 'interrogation-train' } }
          )
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::ADSB.parse_line(line: 'MSG,3,1,1,ABCDEF,...')

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          return { protocol: 'ADSB-UAT', summary: line.strip } unless line.start_with?('MSG,')

          f   = line.split(',', -1)
          out = { protocol: 'ADSB' }
          SBS_FIELDS.each_with_index { |k, i| out[k] = f[i] unless f[i].to_s.empty? }
          bits = []
          bits << "ICAO=#{out[:icao24]}" if out[:icao24]
          bits << "CS=#{out[:callsign].to_s.strip}" if out[:callsign]
          bits << "ALT=#{out[:altitude_ft]}ft" if out[:altitude_ft]
          bits << "POS=#{out[:lat]},#{out[:lon]}" if out[:lat] && out[:lon]
          bits << "GS=#{out[:ground_speed_kt]}kt" if out[:ground_speed_kt]
          bits << "SQK=#{out[:squawk]}" if out[:squawk]
          out[:summary] = "ADSB #{bits.join(' ')}".strip
          out
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE (true-air I/Q via PWN::FFI + detector fallback):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq',
              source:   'optional - :auto|:rtlsdr|:adalm_pluto|:file',
              file:     'optional - .cu8/.cs16 capture at ≥2 Msps'
            )

            #{self}.decode_modes(bits: [0,1,...])   # 56/112 Mode-S bits
            #{self}.parse_line(line: 'MSG,3,1,1,ABCDEF,1,...')

            #{self}.authors
          "
        end
      end
    end
  end
end
