# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby RTTY (Radioteletype, ITA2/Baudot) decoder.
      #
      # Amateur RTTY is 45.45 baud 2-FSK with a 170 Hz shift; on USB the
      # convention is mark ≈ 2125 Hz, space ≈ 2295 Hz in the demodulated
      # audio. This module runs a per-symbol Goertzel on both tones,
      # frames 1-start / 5-data / 1.5-stop asynchronously, and decodes
      # ITA2 via DSP::BAUDOT_LTRS/FIGS. No `minimodem`, no `sox`.
      module RTTY
        # Streaming 2-FSK Baudot demodulator fed by Base.run_native.
        class Demod
          def initialize(rate: 48_000, baud: 45.45, mark_hz: 2125.0, space_hz: 2295.0)
            @rate     = rate
            @baud     = baud
            @mark_hz  = mark_hz
            @space_hz = space_hz
            @spb      = rate / baud
            @buf      = []
            @figs     = false
            @line     = +''
            @idle_bits = 0
          end

          def feed(samples, &)
            @buf.concat(samples)
            # keep at most ~2 s of audio buffered
            @buf.shift(@buf.length - (@rate * 2)) if @buf.length > @rate * 2
            demod_buffer(&)
          end

          private

          def bit_at(offset)
            a = offset.floor
            b = (offset + @spb).floor
            win = @buf[a...b]
            pm = PWN::SDR::Decoder::DSP.goertzel(samples: win, rate: @rate, freq: @mark_hz)
            ps = PWN::SDR::Decoder::DSP.goertzel(samples: win, rate: @rate, freq: @space_hz)
            pm >= ps ? 1 : 0
          end

          # Async framing: idle = mark(1), start bit = space(0), 5 data bits
          # LSB-first, ≥1 stop bit = mark(1).
          def demod_buffer(&)
            char_span = (@spb * 7.5).ceil
            pos = 0.0
            while @buf.length - pos > char_span
              if bit_at(pos) == 1
                pos += @spb
                @idle_bits += 1
                flush_line(&) if @idle_bits > 20 && !@line.empty?
                next
              end
              @idle_bits = 0
              # start bit found — sample 5 data bits at their centres
              data = Array.new(5) { |i| bit_at(pos + (@spb * (i + 1))) }
              stop = bit_at(pos + (@spb * 6))
              pos += @spb * 7.5
              next unless stop == 1

              handle_code(data.each_with_index.sum { |b, i| b << i }, &)
            end
            consumed = pos.floor
            @buf.shift(consumed) if consumed.positive?
          end

          def handle_code(code, &)
            case code
            when 31 then @figs = false
            when 27 then @figs = true
            else
              tbl = @figs ? PWN::SDR::Decoder::DSP::BAUDOT_FIGS : PWN::SDR::Decoder::DSP::BAUDOT_LTRS
              c = tbl[code]
              return unless c

              if ["\n", "\r"].include?(c)
                flush_line(&)
              else
                @line << c
                flush_line(&) if @line.length >= 80
              end
            end
          end

          def flush_line
            return if @line.strip.empty?

            out = { protocol: 'RTTY', baud: @baud, shift_hz: (@space_hz - @mark_hz).round, text: @line.dup }
            if (m = @line.match(/\bDE\s+([A-Z0-9]{1,3}\d[A-Z]{1,4})\b/))
              out[:callsign] = m[1]
            end
            out[:summary] = "RTTY #{@line.strip}"[0, 120]
            yield out
            @line = +''
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::RTTY.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          # Prefer true-air I/Q (FM-demod → existing audio demod) when the
          # operator asks for a source/file or sets freq_obj[:iq_source].
          # Otherwise keep the GQRX 48 kHz UDP audio path (run_native).
          want_iq = opts[:source] || opts[:file] || freq_obj[:iq_source] || freq_obj[:iq_file]
          if want_iq
            PWN::SDR::Decoder::Base.run_iq(
              freq_obj: freq_obj,
              protocol: 'RTTY',
              demod: Demod.new,
              sample_rate: (opts[:sample_rate] || freq_obj[:iq_rate] || 48_000).to_i,
              source: opts[:source],
              file: opts[:file],
              fm_demod: true,
              note: 'RTTY true-air: FM-demod I/Q then native bit recovery; falls back to detector without SDR hardware.'
            )
          else
            PWN::SDR::Decoder::Base.run_native(
              freq_obj: freq_obj,
              protocol: 'RTTY',
              demod: Demod.new
            )
          end
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE (true-air I/Q + GQRX-audio native paths, no external binaries):
            #{self}.decode(
              freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
            )

            NOTE: Set GQRX to USB, tune so mark≈2125 Hz / space≈2295 Hz in
                  the audio passband. 45.45 baud, 170 Hz shift, 1N5+1.5.

            #{self}.authors
          "
        end
      end
    end
  end
end
