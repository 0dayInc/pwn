# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby POCSAG (CCIR Radiopaging Code No. 1) decoder.
      #
      # GQRX supplies NBFM-discriminator audio on its 48 kHz UDP tap; for a
      # 2-FSK pager channel that is already an NRZ baseband whose sign
      # encodes the bit. This module NRZ-slices at 512/1200/2400 baud,
      # locks onto the 32-bit Frame Sync Codeword (0x7CD215D8), then walks
      # each 8-frame batch of BCH(31,21)+parity codewords, extracting
      # address (RIC/capcode + function bits) and message codewords
      # (numeric BCD or 7-bit ASCII). No `multimon-ng`, no `sox`.
      module POCSAG
        FSC       = 0x7CD215D8
        IDLE_CW   = 0x7A89C197
        BAUDS     = [1200, 512, 2400].freeze
        BCD_TABLE = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', 'U', ' ', '-', ')', '('].freeze

        FUNCTION_DESC = {
          0 => 'Numeric (Tone/A)',
          1 => 'Tone only (B)',
          2 => 'Tone only (C)',
          3 => 'Alphanumeric (D)'
        }.freeze

        # Streaming POCSAG demodulator fed by Base.run_native.
        class Demod
          def initialize(rate: 48_000)
            @rate  = rate
            @buf   = []
            @baud  = nil
            @inv   = false
            @carry_bits = []
          end

          def feed(samples, &)
            @buf.concat(samples)
            max = (@rate * 3.5).to_i
            @buf.shift(@buf.length - max) if @buf.length > max
            return if @buf.length < @rate # need ≥1 s to lock

            try_lock unless @baud
            return unless @baud

            bits = PWN::SDR::Decoder::DSP.nrz_slice(samples: @buf, rate: @rate, baud: @baud, invert: @inv)
            @buf.clear
            bits = @carry_bits + bits
            @carry_bits = POCSAG.decode_bits(bits: bits, baud: @baud, &)
          end

          private

          # Try each baud × polarity until FSC (≤2 bit errors) is found.
          def try_lock
            hit = BAUDS.product([false, true]).find do |bd, inv|
              bits = PWN::SDR::Decoder::DSP.nrz_slice(samples: @buf, rate: @rate, baud: bd, invert: inv)
              PWN::SDR::Decoder::DSP.find_sync(bits: bits, pattern: FSC, width: 32, max_err: 2)
            end
            @baud, @inv = hit if hit
          end
        end

        # Supported Method Parameters::
        # carry = PWN::SDR::Decoder::POCSAG.decode_bits(bits: [...], baud: 1200) { |msg| ... }
        # Returns the trailing (unconsumed) bits so the caller can prepend
        # them to the next chunk for streaming continuity.

        public_class_method def self.decode_bits(opts = {})
          bits = opts[:bits] || []
          baud = opts[:baud]
          i = 0
          pending = nil
          flush = proc do
            yield assemble(pending: pending, baud: baud) if pending && block_given?
            pending = nil
          end
          loop do
            idx = PWN::SDR::Decoder::DSP.find_sync(bits: bits, pattern: FSC, width: 32, max_err: 2, from: i)
            break unless idx

            i = idx + 32
            # One batch = 8 frames × 2 codewords × 32 bits = 512 bits
            8.times do |frame|
              2.times do
                break if i + 32 > bits.length

                cw = PWN::SDR::Decoder::DSP.bits_to_int(bits: bits[i, 32])
                i += 32
                next if [IDLE_CW, FSC].include?(cw)

                if cw.nobits?(0x80000000)
                  flush.call
                  addr18 = (cw >> 13) & 0x3FFFF
                  func   = (cw >> 11) & 0x3
                  ric    = (addr18 << 3) | frame
                  pending = { ric: ric, func: func, msg_words: [] }
                elsif pending
                  pending[:msg_words] << ((cw >> 11) & 0xFFFFF)
                end
              end
            end
          end
          flush.call
          tail_from = [bits.length - 576, 0].max
          bits[tail_from..] || []
        end

        # Supported Method Parameters::
        # h = PWN::SDR::Decoder::POCSAG.assemble(pending: {ric:,func:,msg_words:}, baud: 1200)

        public_class_method def self.assemble(opts = {})
          pending = opts[:pending]
          baud    = opts[:baud]
          return {} unless pending

          words = pending[:msg_words] || []
          func  = pending[:func]
          type, text =
            if words.empty?
              ['Tone', nil]
            elsif func == 3
              ['Alpha', alpha_decode(words: words)]
            else
              ['Numeric', numeric_decode(words: words)]
            end
          out = {
            protocol: 'POCSAG',
            baud: baud,
            address: pending[:ric],
            capcode: pending[:ric].to_s.rjust(7, '0'),
            function: func,
            function_desc: FUNCTION_DESC[func] || 'Unknown',
            type: type,
            message: text
          }.compact
          summary = ["POCSAG#{baud}", "RIC=#{out[:capcode]}", "F#{func}(#{out[:function_desc]})"]
          summary << "#{type}: #{text}" if text
          out[:summary] = summary.join(' ')
          out
        end

        # Supported Method Parameters::
        # str = PWN::SDR::Decoder::POCSAG.numeric_decode(words: [Integer, ...])

        public_class_method def self.numeric_decode(opts = {})
          words = opts[:words] || []
          out = +''
          words.each do |w|
            5.times do |d|
              nib = (w >> (16 - (d * 4))) & 0xF
              # POCSAG BCD nibbles are bit-reversed within each 4-bit group
              rev = ((nib & 1) << 3) | ((nib & 2) << 1) | ((nib & 4) >> 1) | ((nib & 8) >> 3)
              out << BCD_TABLE[rev]
            end
          end
          out.gsub(/ +$/, '')
        end

        # Supported Method Parameters::
        # str = PWN::SDR::Decoder::POCSAG.alpha_decode(words: [Integer, ...])

        public_class_method def self.alpha_decode(opts = {})
          words = opts[:words] || []
          bitstream = []
          words.each do |w|
            19.downto(0) { |b| bitstream << ((w >> b) & 1) }
          end
          out = +''
          bitstream.each_slice(7) do |ch|
            break if ch.length < 7

            # 7-bit ASCII, LSB first within each character
            code = ch.each_with_index.sum { |b, i| b << i }
            next if code.zero? || code == 0x03 || code == 0x17

            out << (code.between?(0x20, 0x7E) ? code.chr : '.')
          end
          out.strip
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::POCSAG.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          PWN::SDR::Decoder::Base.run_native(
            freq_obj: freq_obj,
            protocol: 'POCSAG',
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

            #{self}.decode_bits(bits: [0,1,...], baud: 1200) { |msg| ... }
            #{self}.assemble(pending: {ric:, func:, msg_words:[]}, baud: 1200)
            #{self}.numeric_decode(words: [Integer, ...])
            #{self}.alpha_decode(words: [Integer, ...])

            NOTE: Set GQRX to Narrow FM. Baud (512/1200/2400) and NRZ
                  polarity are auto-detected from the FSC 0x7CD215D8.

            #{self}.authors
          "
        end
      end
    end
  end
end
