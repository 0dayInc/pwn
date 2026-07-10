# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # IEEE 802.15.4 O-QPSK (2.4 GHz ZigBee/Thread) true-air decoder.
      #
      # 2 Mchip/s half-sine O-QPSK ≡ MSK, so I/Q → PWN::FFI::Liquid
      # gmskdem (BT=0.5) at 2 Msps → chip stream. Each 4-bit symbol maps
      # to a 32-chip PN sequence (Table 73, IEEE 802.15.4-2011); soft-
      # correlate every 32 chips against the 16 sequences → symbols →
      # nibbles → bytes. Hunt SHR (4×0x00 preamble + SFD 0xA7) → PHR len
      # → MHR (FCF/seq/PAN/addr) → FCS (CRC-16-KERMIT). Emits per-frame
      # {pan_id:, src:, dst:, frame_type:, len:, fcs_ok:}.
      module ZigBee
        CHIP_RATE = 2_000_000
        # 16 × 32-chip PN sequences (symbol 0..15). Each row is one 32-bit
        # word; chips are LSB-first (c0 = bit0).
        PN32 = [
          0xD9C3522E, 0xED9C3522, 0x2ED9C352, 0x22ED9C35,
          0x522ED9C3, 0x3522ED9C, 0xC3522ED9, 0x9C3522ED,
          0x8C96077B, 0xB8C96077, 0x7B8C9607, 0x77B8C960,
          0x077B8C96, 0x6077B8C9, 0x96077B8C, 0xC96077B8
        ].freeze
        PN_CHIPS = PN32.map { |w| Array.new(32) { |i| (w >> i) & 1 } }.freeze
        SFD = 0xA7
        FRAME_TYPE = { 0 => 'Beacon', 1 => 'Data', 2 => 'ACK', 3 => 'MAC-Cmd' }.freeze

        # Streaming O-QPSK/MSK chip demod for Base.run_iq — I/Q → 802.15.4 MPDU.
        class DemodIQ
          def initialize(rate:, channel: nil)
            @rate    = rate.to_f
            @channel = channel
            @chips   = []
            @seen    = {}
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            chips = PWN::SDR::Decoder::DSP.gfsk_slice(
              iq: samples, rate: @rate, baud: CHIP_RATE, bt: 0.5
            )
            @chips.concat(chips)
            scan(&) if block_given?
            @chips.shift(@chips.length - 8192) if @chips.length > 65_536
          end

          private

          def correlate_symbol(win)
            best = [0, -1]
            PN_CHIPS.each_with_index do |pn, sym|
              # ±1 correlation, ignore chip0/16 (Q-branch alignment tolerance)
              s = 0
              32.times { |i| s += (win[i] == pn[i] ? 1 : -1) }
              best = [sym, s] if s > best[1]
            end
            best
          end

          def chips_to_bytes(chips)
            nsym = chips.length / 32
            syms = Array.new(nsym) { |i| correlate_symbol(chips[i * 32, 32]).first }
            # two nibbles → byte, LSB-nibble first (symbol 2n = low nibble)
            out = []
            syms.each_slice(2) { |lo, hi| out << ((hi.to_i << 4) | lo.to_i) if hi }
            out
          end

          def scan(&)
            # sliding-align on 32-chip boundary until 4 consecutive sym-0
            i = 0
            while i <= @chips.length - (32 * 12)
              ok = true
              4.times do |p|
                sym, sc = correlate_symbol(@chips[i + (p * 32), 32])
                ok &&= sym.zero? && sc >= 20
                break unless ok
              end
              if ok
                # SFD (0xA7 = symbols 0x7, 0xA)
                s5, = correlate_symbol(@chips[i + (8 * 32), 32])
                s6, = correlate_symbol(@chips[i + (9 * 32), 32])
                if s5 == 0x7 && s6 == 0xA
                  yield_frame(i, &)
                  # skip past SHR
                  i += 32 * 10
                  next
                end
              end
              i += 1
            end
            @chips.shift([i - 32, 0].max) if i > 32
          end

          def yield_frame(shr_i)
            phr_i = shr_i + (32 * 10)
            return if phr_i + (32 * 2) > @chips.length

            phr = chips_to_bytes(@chips[phr_i, 32 * 2]).first.to_i & 0x7F
            body_i = phr_i + (32 * 2)
            return if body_i + (phr * 32 * 2) > @chips.length

            bytes = chips_to_bytes(@chips[body_i, phr * 32 * 2])
            return if bytes.length < 3

            fcs_rx = bytes[-2].to_i | (bytes[-1].to_i << 8)
            fcs_ok = PWN::SDR::Decoder::DSP.crc16(
              bytes: bytes[0, bytes.length - 2], poly: 0x1021,
              init: 0x0000, refin: true, refout: true
            ) == fcs_rx
            fcf = bytes[0].to_i | (bytes[1].to_i << 8)
            ftype = fcf & 0x7
            seq   = bytes[2]
            dst_mode = (fcf >> 10) & 0x3
            src_mode = (fcf >> 14) & 0x3
            j = 3
            pan = dst = src = nil
            if dst_mode.positive?
              pan = bytes[j, 2]&.reverse&.map { |b| format('%02X', b) }&.join
              j += 2
              dl = dst_mode == 3 ? 8 : 2
              dst = bytes[j, dl]&.reverse&.map { |b| format('%02X', b) }&.join
              j += dl
            end
            if src_mode.positive?
              j += 2 unless (fcf >> 6).allbits?(1) # PAN-ID compression
              sl = src_mode == 3 ? 8 : 2
              src = bytes[j, sl]&.reverse&.map { |b| format('%02X', b) }&.join
            end
            key = "#{pan}:#{src}:#{seq}"
            return if @seen[key]

            @seen[key] = true
            @seen.shift if @seen.length > 128
            yield(
              protocol: 'ZigBee', event: 'mpdu', modulation: 'O-QPSK',
              channel: @channel, len: phr, seq: seq,
              frame_type: FRAME_TYPE[ftype] || ftype, fcf: format('%04X', fcf),
              pan_id: pan, dst: dst, src: src, fcs_ok: fcs_ok,
              payload_hex: bytes.map { |b| format('%02X', b) }.join,
              summary: "802.15.4 #{FRAME_TYPE[ftype] || ftype} PAN=#{pan} #{src}→#{dst} seq=#{seq} len=#{phr} FCS=#{fcs_ok ? 'OK' : 'BAD'}"
            )
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::ZigBee.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          hz = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          ch = ((hz - 2_405_000_000) / 5_000_000).round + 11
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 4_000_000).to_i
          PWN::SDR::Decoder::Base.run_iq(
            freq_obj: freq_obj,
            protocol: 'ZigBee',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate, channel: ch),
            note: 'O-QPSK 2 Mcps ≡ MSK — I/Q→gmskdem→32-chip PN correlate→SHR/SFD→PHR/MHR/FCS.',
            describe: proc { |b| { modulation: 'O-QPSK', channel: ch, classification: b[:duration_ms] < 5 ? 'ACK' : 'MAC-frame' } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'ZigBee' }
          out[:pan] = ::Regexp.last_match(1) if line =~ /PAN[:= ]+([0-9A-Fa-f]+)/i
          out[:src] = ::Regexp.last_match(1) if line =~ /src[:= ]+([0-9A-Fa-f:]+)/i
          out[:dst] = ::Regexp.last_match(1) if line =~ /dst[:= ]+([0-9A-Fa-f:]+)/i
          out[:cmd] = ::Regexp.last_match(1) if line =~ /\b(Beacon|Data|ACK|Cmd)\b/i
          out[:summary] = "ZigBee #{out[:cmd]} PAN=#{out[:pan]} #{out[:src]}→#{out[:dst]}"
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
              file:     'optional - .cu8/.cs16 capture (≥4 Msps)'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
