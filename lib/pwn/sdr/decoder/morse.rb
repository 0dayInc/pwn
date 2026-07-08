# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby CW / Morse decoder for the amateur CW sub-bands.
      #
      # GQRX's CW/USB demodulator produces a ~600–800 Hz sidetone in the
      # 48 kHz UDP audio stream. This module envelope-detects the tone
      # with a state-preserving single-pole low-pass, adaptively
      # thresholds it into on/off runs, classifies each run as dit / dah
      # / char-gap / word-gap by timing, and looks the resulting `.-`
      # sequences up in DSP::MORSE_TABLE. No `multimon-ng`, no `sox`.
      module Morse
        # Stateful, streaming CW demodulator fed by Base.run_native.
        class Demod
          def initialize(rate: 48_000)
            @rate    = rate
            # single-pole low-pass on |x|; τ ≈ 5 ms
            @env_a   = Math.exp(-1.0 / (rate * 0.005))
            @env     = 0.0
            @floor   = 0.0
            @peak    = 0.0
            @state   = :off
            @run     = 0
            @dit     = rate * 60 / 1000 # seed 60 ms (≈ 20 WPM)
            @sym     = +''
            @word    = +''
          end

          def feed(samples, &)
            samples.each do |x|
              @env = (@env_a * @env) + ((1.0 - @env_a) * x.abs)
              # slow trackers for adaptive threshold (attack fast, decay slow)
              @peak  = @env > @peak ? ((@peak * 0.7) + (@env * 0.3)) : (@peak * 0.9999)
              @floor = @env < @floor ? @env : ((@floor * 0.9999) + (@env * 0.0001))
              thresh = @floor + ((@peak - @floor) * 0.4)
              on = @env > thresh && (@peak - @floor) > 0.01
              if on == (@state == :on)
                @run += 1
              else
                classify_run(&)
                @state = on ? :on : :off
                @run   = 1
              end
            end
            return unless @state == :off && @run > 5 * @dit && !(@sym.empty? && @word.empty?)

            flush_char
            flush_word(&)
          end

          private

          def classify_run(&)
            return if @run < @rate / 500 # <2 ms glitch

            if @state == :on
              @dit = ((@dit * 3) + @run) / 4 if @run < @dit * 1.5 && @run > @rate / 200
              @sym << (@run > 2 * @dit ? '-' : '.')
            else
              return if @sym.empty? && @word.empty?

              if @run > 5 * @dit
                flush_char
                flush_word(&)
              elsif @run > 2 * @dit
                flush_char
              end
            end
          end

          def flush_char
            return if @sym.empty?

            @word << (PWN::SDR::Decoder::DSP::MORSE_TABLE[@sym] || '_')
            @sym = +''
          end

          def flush_word
            return if @word.empty?

            out = { protocol: 'MORSE-CW', text: @word.dup }
            if (m = @word.match(/\b([A-Z0-9]{1,3}\d[A-Z]{1,4})\b/))
              out[:callsign] = m[1]
            end
            out[:summary] = "CW #{@word}"[0, 120]
            yield out
            @word = +''
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Morse.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          PWN::SDR::Decoder::Base.run_native(
            freq_obj: freq_obj,
            protocol: 'MORSE-CW',
            demod: Demod.new
          )
        end

        # Supported Method Parameters::
        # h = PWN::SDR::Decoder::Morse.decode_string(pattern: '.- -...')

        public_class_method def self.decode_string(opts = {})
          pattern = opts[:pattern].to_s
          txt = pattern.strip.split(/\s+/).map { |s| PWN::SDR::Decoder::DSP::MORSE_TABLE[s] || '_' }.join
          { protocol: 'MORSE-CW', text: txt, summary: "CW #{txt}" }
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

            #{self}.decode_string(pattern: '.- -...')

            #{self}.authors
          "
        end
      end
    end
  end
end
