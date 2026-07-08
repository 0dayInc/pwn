# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby combined pager decoder for the mixed-protocol `pager_all`
      # band plan. Feeds every incoming 48 kHz audio chunk to BOTH the
      # native POCSAG and FLEX demodulators concurrently; whichever locks
      # emits messages. No `multimon-ng`, no `sox`.
      module Pager
        # Composite demodulator wrapping POCSAG::Demod + Flex::Demod.
        class Demod
          def initialize(rate: 48_000)
            @pocsag = PWN::SDR::Decoder::POCSAG::Demod.new(rate: rate)
            @flex   = PWN::SDR::Decoder::Flex::Demod.new(rate: rate)
          end

          def feed(samples, &)
            @pocsag.feed(samples.dup, &)
            @flex.feed(samples, &)
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Pager.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          PWN::SDR::Decoder::Base.run_native(
            freq_obj: freq_obj,
            protocol: 'PAGER',
            demod: Demod.new
          )
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

            NOTE: Runs the native POCSAG (512/1200/2400) and FLEX (1600)
                  demodulators in parallel on the same GQRX NBFM audio tap.

            #{self}.authors
          "
        end
      end
    end
  end
end
