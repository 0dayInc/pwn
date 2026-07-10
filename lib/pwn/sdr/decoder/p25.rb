# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # APCO Project 25 Phase-1 (C4FM) true-air decoder.
      #
      # I/Q → PWN::FFI::Liquid.freq_demod (or DSP.fm_demod_iq) → resample to
      # 48 kHz → 4-level slice at 4800 sym/s → dibits → hunt the 24-symbol
      # Frame Sync (0x5575F5FF77FF) → recover the 64-bit NID (12-bit NAC +
      # 4-bit DUID + BCH(63,16,23) parity). Emits {nac:, duid:, duid_name:}
      # per frame — the same intel OP25 / DSD show — with no external binary.
      module P25
        # 24-symbol / 48-bit Frame Sync (dibit MSB-first)
        FS_DIBITS = [
          1, 1, 1, 1, 3, 1, 1, 3, 3, 3, 3, 1, 1, 3, 3, 3,
          3, 3, 3, 3, 1, 3, 3, 3, 3, 3, 3, 3
        ].freeze # → 0x5575F5FF77FF (see TIA-102.BAAA)
        FS_DIBITS_24 = [
          1, 1, 1, 1, 3, 1, 1, 3, 3, 3, 3, 1,
          3, 3, 1, 1, 3, 3, 3, 3, 3, 3, 3, 3
        ].freeze
        # Correct 24-dibit Frame Sync per TIA-102 (+3 +3 +3 +3 −3 +3 …).
        # Derived from bit pattern 5575F5FF77FF, MSB-first, 2 bits/sym,
        # C4FM map: 01→+3, 00→+1, 10→−1, 11→−3 → dibits {1,0,2,3}.
        FRAME_SYNC = 0x5575F5FF77FF
        FS_BITS = Array.new(48) { |i| (FRAME_SYNC >> (47 - i)) & 1 }.freeze
        FS_SYMS = FS_BITS.each_slice(2).map { |a, b| (a << 1) | b }.freeze

        DUID_NAME = {
          0x0 => 'HDU', 0x3 => 'TDU', 0x5 => 'LDU1', 0x7 => 'TSBK',
          0xA => 'LDU2', 0xC => 'PDU', 0xF => 'TDULC'
        }.freeze

        # Streaming C4FM demod for Base.run_iq — I/Q → NAC/DUID frames.
        class DemodIQ
          AUDIO_RATE = 48_000

          def initialize(rate:)
            @rate = rate.to_f
            @dibits = []
            @seen_fs = 0
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            audio = PWN::SDR::Decoder::DSP.fm_demod_iq(iq: samples)
            audio = PWN::SDR::Decoder::DSP.resample(
              samples: audio, src_rate: @rate, dst_rate: AUDIO_RATE
            )
            syms = PWN::SDR::Decoder::DSP.slice_4fsk(
              samples: audio, rate: AUDIO_RATE, baud: 4800
            )
            @dibits.concat(syms)
            scan(&) if block_given?
            @dibits.shift(@dibits.length - 4096) if @dibits.length > 8192
          end

          private

          def scan
            fs = P25::FS_SYMS
            i = 0
            while i <= @dibits.length - (24 + 32)
              # Allow up to 3 symbol errors on FS
              err = 0
              j = 0
              while j < 24
                err += 1 if @dibits[i + j] != fs[j]
                break if err > 3

                j += 1
              end
              if err <= 3
                nid_syms = @dibits[i + 24, 32] # 32 dibits = 64 bits
                nid_bits = nid_syms.flat_map { |d| [(d >> 1) & 1, d & 1] }
                nid = PWN::SDR::Decoder::DSP.bits_to_int(bits: nid_bits[0, 16])
                nac = (nid >> 4) & 0xFFF
                duid = nid & 0xF
                @seen_fs += 1
                yield(
                  protocol: 'P25', event: 'frame', modulation: 'C4FM',
                  fs_errors: err, nac: format('%03X', nac), duid: duid,
                  duid_name: P25::DUID_NAME[duid] || format('0x%X', duid),
                  nid_hex: format('%016X', PWN::SDR::Decoder::DSP.bits_to_int(bits: nid_bits)),
                  frame_no: @seen_fs,
                  summary: "P25 NAC=#{format('%03X', nac)} DUID=#{P25::DUID_NAME[duid] || duid} (fs_err=#{err})"
                )
                i += 24 + 32
              else
                i += 1
              end
            end
            @dibits.shift([i - 24, 0].max) if i > 24
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::P25.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || (48_000 * 20)).to_i
          PWN::SDR::Decoder::Base.run_iq(
            freq_obj: freq_obj,
            protocol: 'P25',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate),
            note: 'C4FM 4800 sym/s — I/Q→FM→4-FSK→FS 0x5575F5FF77FF→NAC/DUID.',
            describe: proc { |b| { modulation: 'C4FM', classification: b[:duration_ms] > 180 ? 'voice-LDU' : 'TSBK/control' } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'P25' }
          out[:nac]  = ::Regexp.last_match(1) if line =~ /NAC[:= ]+([0-9A-Fa-f]+)/
          out[:tg]   = ::Regexp.last_match(1) if line =~ /(?:TG|talkgroup)[:= ]+(\d+)/i
          out[:rid]  = ::Regexp.last_match(1) if line =~ /(?:RID|src|source)[:= ]+(\d+)/i
          out[:duid] = ::Regexp.last_match(1) if line =~ /DUID[:= ]+(\w+)/i
          out[:summary] = "P25 NAC=#{out[:nac]} TG=#{out[:tg]} RID=#{out[:rid]}"
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
              file:     'optional - .cu8/.cs16 capture'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
