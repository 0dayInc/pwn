# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby NOAA APT (Automatic Picture Transmission) decoder for the
      # 137 MHz polar-orbiting weather satellites (NOAA-15/18/19).
      #
      # APT is a 2400 Hz AM subcarrier inside a ~34 kHz-wide FM downlink
      # carrying two 909-pixel image channels at 2 lines/second (4160
      # words/line). This module envelope-demodulates the 2400 Hz carrier
      # from GQRX's 48 kHz UDP audio, resamples to 4160 words/sec, aligns
      # each line on the 7-pulse Sync-A pattern, and appends the resulting
      # 8-bit greyscale rows to a Netpbm PGM (P5) file — all in Ruby.
      # No `sox`, no `noaa-apt`.
      module APT
        WORDS_PER_LINE = 4160
        LINES_PER_SEC  = 2
        WORD_RATE      = WORDS_PER_LINE * LINES_PER_SEC # 8320 Hz
        # Sync-A: 7 cycles of 1040 Hz square = 1 1 0 0 repeated 7 times
        SYNC_A = ([1, 1, 0, 0] * 7).freeze

        # Streaming APT demodulator fed by Base.run_native.
        class Demod
          def initialize(rate: 48_000, out_path: nil)
            @rate     = rate
            @carrier  = 2400.0
            @env_win  = (rate / @carrier).round # ≈20 samples per cycle
            @stamp    = Time.now.strftime('%Y%m%d_%H%M%S')
            @pgm_path = out_path || "/tmp/apt_#{@stamp}.pgm"
            @rows     = []
            @word_buf = []
            @minv     = 1.0
            @maxv     = 0.0
          end

          def feed(samples, &)
            env   = PWN::SDR::Decoder::DSP.envelope(samples: samples, window: @env_win)
            words = PWN::SDR::Decoder::DSP.resample(samples: env, src_rate: @rate, dst_rate: WORD_RATE)
            @word_buf.concat(words)
            extract_lines(&)
          end

          private

          def extract_lines
            while @word_buf.length >= WORDS_PER_LINE * 2
              off = sync_offset(@word_buf[0, WORDS_PER_LINE])
              @word_buf.shift(off) if off.positive?
              break if @word_buf.length < WORDS_PER_LINE

              row = @word_buf.shift(WORDS_PER_LINE)
              lo, hi = row.minmax
              @minv = lo if lo < @minv
              @maxv = hi if hi > @maxv
              @rows << row
              write_pgm if (@rows.length % 20).zero?
              yield(
                protocol: 'NOAA-APT',
                lines: @rows.length,
                seconds: @rows.length / LINES_PER_SEC,
                pgm: @pgm_path,
                summary: "APT line #{@rows.length} (#{@rows.length / LINES_PER_SEC}s) → #{@pgm_path}"
              )
            end
          end

          def sync_offset(row)
            mid = row.sum / row.length
            best_off = 0
            best_cor = -1.0
            (0..(row.length - SYNC_A.length)).each do |o|
              cor = 0.0
              SYNC_A.each_with_index do |s, i|
                cor += (row[o + i] - mid) * (s.zero? ? -1.0 : 1.0)
              end
              if cor > best_cor
                best_cor = cor
                best_off = o
              end
            end
            best_off
          end

          def write_pgm
            span = @maxv - @minv
            span = 1.0 if span <= 0
            File.open(@pgm_path, 'wb') do |f|
              f.write("P5\n#{WORDS_PER_LINE} #{@rows.length}\n255\n")
              @rows.each do |row|
                bytes = row.map { |v| (((v - @minv) / span) * 255).clamp(0, 255).round }
                f.write(bytes.pack('C*'))
              end
            end
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::APT.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          want_iq = opts[:source] || opts[:file] || freq_obj[:iq_source] || freq_obj[:iq_file]
          if want_iq
            PWN::SDR::Decoder::Base.run_iq(
              freq_obj: freq_obj,
              protocol: 'NOAA-APT',
              demod: Demod.new(out_path: opts[:out_path]),
              sample_rate: (opts[:sample_rate] || freq_obj[:iq_rate] || 48_000).to_i,
              source: opts[:source],
              file: opts[:file],
              fm_demod: true,
              note: 'NOAA APT true-air: FM-demod I/Q then 2400 Hz AM envelope → PGM.'
            )
          else
            PWN::SDR::Decoder::Base.run_native(
              freq_obj: freq_obj,
              protocol: 'NOAA-APT',
              demod: Demod.new(out_path: opts[:out_path])
            )
          end
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE (ruby-native, no external binaries):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            NOTE: Set GQRX to WFM (mono), ~34 kHz filter. Writes an 8-bit
                  greyscale Netpbm P5 image to /tmp/apt_<ts>.pgm every 10 s
                  of received pass. Both A/B channels are in one strip.

            #{self}.authors
          "
        end
      end
    end
  end
end
