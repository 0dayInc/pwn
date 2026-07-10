# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # GSM (2G) true-air FCCH/SCH decoder.
      #
      # 270.833 kbit/s GMSK. FCCH burst = 148 all-zero bits → a pure
      # +67.708 kHz tone for ~547 μs. Detect via variance-dip on the FM
      # discriminator (PWN::FFI::Liquid.freq_demod), estimate carrier
      # offset from mean deviation, then correlate the SCH 64-bit extended
      # training sequence 8 timeslots later and recover the 6-bit BSIC
      # (NCC/BCC) + 19-bit reduced frame number (T1/T2/T3'). Emits
      # {event:'fcch'|'sch', freq_offset_hz:, bsic:, ncc:, bcc:, rfn:}.
      module GSM
        SYMBOL_RATE = 270_833.0
        FCCH_TONE   = SYMBOL_RATE / 4.0 # 67.708 kHz above carrier
        FCCH_BITS   = 148
        # SCH extended training sequence (64 bits, TS 45.002 Table 5.2.5)
        SCH_ETSC = [
          1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0,
          0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,
          0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1,
          0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1
        ].freeze

        # Streaming GMSK demod for Base.run_iq — I/Q → FCCH lock + SCH BSIC.
        class DemodIQ
          def initialize(rate:)
            @rate  = rate.to_f
            @spb   = @rate / SYMBOL_RATE
            @audio = []
            @fcch_n = 0
            @sch_n  = 0
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            @spb  = @rate / SYMBOL_RATE
            fm = PWN::SDR::Decoder::DSP.fm_demod_iq(iq: samples)
            @audio.concat(fm)
            scan(&) if block_given?
            max = (@rate * 0.25).to_i
            @audio.shift(@audio.length - max) if @audio.length > max
          end

          private

          def scan
            win = (FCCH_BITS * @spb).round
            return if @audio.length < win * 4

            # slide half-burst hop, look for min-variance window (pure tone)
            hop  = win / 4
            best = nil
            i = 0
            while i < @audio.length - win
              seg  = @audio[i, win]
              mean = seg.sum / seg.length
              var  = seg.sum { |v| (v - mean)**2 } / seg.length
              best = { i: i, mean: mean, var: var } if best.nil? || var < best[:var]
              i += hop
            end
            return unless best

            # FCCH criterion: variance ≪ overall variance AND mean > 0.
            g_mean = @audio.sum / @audio.length
            g_var  = @audio.sum { |v| (v - g_mean)**2 } / @audio.length
            return unless g_var.positive? && (best[:var] / g_var) < 0.15 && best[:mean].positive?

            @fcch_n += 1
            # discriminator output ≈ 2π·Δf/fs → Δf = mean · fs / (2π)
            f_est = best[:mean] * @rate / (2 * Math::PI)
            f_off = (f_est - FCCH_TONE).round
            yield(
              protocol: 'GSM', event: 'fcch', modulation: 'GMSK',
              symbol_rate: SYMBOL_RATE.to_i, fcch_no: @fcch_n,
              tone_hz: f_est.round, freq_offset_hz: f_off,
              variance_ratio: (best[:var] / g_var).round(4),
              summary: "GSM FCCH lock ##{@fcch_n} tone=#{f_est.round}Hz Δf=#{f_off}Hz"
            )

            # SCH lives 8 timeslots after FCCH: 8 × 156.25 = 1250 symbols.
            sch_off = best[:i] + (1250 * @spb).round
            return unless sch_off + (148 * @spb).round < @audio.length

            seg  = @audio[sch_off, (156 * @spb).round]
            bits = PWN::SDR::Decoder::DSP.nrz_slice(
              samples: seg, rate: @rate, baud: SYMBOL_RATE
            )
            # GMSK data are differentially encoded (1 = no phase change).
            db = PWN::SDR::Decoder::DSP.diff_decode(bits: bits).map { |b| b ^ 1 }
            idx = PWN::SDR::Decoder::DSP.find_sync(
              bits: db, pattern: SCH_ETSC, max_err: 8
            )
            return unless idx && idx >= 42 && idx + 64 + 39 <= db.length

            # SCH burst: 3 tail + 39 enc + 64 TS + 39 enc + 3 tail + 8.25 guard
            enc1 = db[idx - 39, 39]
            enc2 = db[idx + 64, 39]
            enc  = enc1 + enc2 # 78 coded bits (rate-1/2 conv, K=5)
            info = GSM.viterbi_decode(bits: enc, k: 5, g0: 0o23, g1: 0o33)
            # 25 info bits + 10 parity + 4 tail = 39 → we get first 39.
            bsic = PWN::SDR::Decoder::DSP.bits_to_int(bits: info[0, 6])
            t1   = PWN::SDR::Decoder::DSP.bits_to_int(bits: info[6, 11])
            t2   = PWN::SDR::Decoder::DSP.bits_to_int(bits: info[17, 5])
            t3p  = PWN::SDR::Decoder::DSP.bits_to_int(bits: info[22, 3])
            @sch_n += 1
            yield(
              protocol: 'GSM', event: 'sch', modulation: 'GMSK',
              bsic: bsic, ncc: (bsic >> 3) & 7, bcc: bsic & 7,
              t1: t1, t2: t2, t3p: t3p, sch_no: @sch_n,
              raw_info_hex: info[0, 25].each_slice(4).map { |n| PWN::SDR::Decoder::DSP.bits_to_int(bits: n).to_s(16) }.join,
              summary: "GSM SCH BSIC=#{bsic} (NCC=#{(bsic >> 3) & 7} BCC=#{bsic & 7}) T1=#{t1} T2=#{t2} T3'=#{t3p}"
            )
            # consume up to & incl. SCH so we don't re-emit on next feed
            @audio.shift(sch_off + (156 * @spb).round)
          end
        end

        # Supported Method Parameters::
        # bits = PWN::SDR::Decoder::GSM.viterbi_decode(
        #   bits: 'required - Array<0|1> soft/hard coded bits (rate-1/2)',
        #   k: 5, g0: 0o23, g1: 0o33
        # )
        # Minimal hard-decision K=5 rate-½ Viterbi (GSM 05.03 CC(2,1,5)).

        public_class_method def self.viterbi_decode(opts = {})
          bits = opts[:bits]
          k    = (opts[:k] || 5).to_i
          g0   = (opts[:g0] || 0o23).to_i
          g1   = (opts[:g1] || 0o33).to_i
          nstates = 1 << (k - 1)
          npairs  = bits.length / 2
          pm = Array.new(nstates, 1 << 30)
          pm[0] = 0
          bp = Array.new(npairs) { Array.new(nstates, 0) }
          npairs.times do |t|
            r0 = bits[t * 2]
            r1 = bits[(t * 2) + 1]
            npm = Array.new(nstates, 1 << 30)
            nstates.times do |s|
              [0, 1].each do |u|
                reg = (u << (k - 1)) | s
                o0 = parity(reg & g0)
                o1 = parity(reg & g1)
                m  = pm[s] + (o0 == r0 ? 0 : 1) + (o1 == r1 ? 0 : 1)
                ns = reg >> 1
                if m < npm[ns]
                  npm[ns] = m
                  bp[t][ns] = (s << 1) | u
                end
              end
            end
            pm = npm
          end
          # traceback from best final state
          s = pm.each_with_index.min_by(&:first).last
          out = Array.new(npairs)
          (npairs - 1).downto(0) do |t|
            v = bp[t][s]
            out[t] = v & 1
            s = v >> 1
          end
          out
        end

        public_class_method def self.parity(opts = {})
          parity = opts[:parity].to_i
          p = 0
          while parity.positive?
            p ^= 1
            parity &= parity - 1
          end
          p
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::GSM.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 1_083_333).to_i
          PWN::SDR::Decoder::Base.run_iq(
            freq_obj: freq_obj,
            protocol: 'GSM',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate),
            note: '270.833 kbit/s GMSK — I/Q→freqdem→FCCH tone lock→SCH TS correlate→Viterbi→BSIC/RFN.',
            describe: proc { |b| { modulation: 'GMSK', tdma_frames: (b[:duration_ms] / 4.615).round } }
          )
        end

        TSHARK_FIELDS = %w[
          frame.time gsmtap.arfcn gsmtap.chan_type gsm_a.imsi gsm_a.tmsi
          e212.mcc e212.mnc gsm_a.lac gsm_a.bssmap.cell_ci gsm_a.dtap.msg_rr_type
        ].freeze

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          f = line.split('|', -1)
          out = {
            protocol: 'GSM', frame_time: f[0], arfcn: f[1], chan_type: f[2],
            imsi: f[3], tmsi: f[4], mcc: f[5], mnc: f[6], lac: f[7],
            cell_id: f[8], rr_msg_type: f[9]
          }.reject { |_, v| v.to_s.empty? }
          if out[:imsi].to_s.length.between?(14, 16)
            out[:imsi_mcc]  = out[:imsi][0, 3]
            out[:imsi_mnc]  = out[:imsi][3, 3]
            out[:imsi_msin] = out[:imsi][6..]
          end
          bits = []
          bits << "ARFCN=#{out[:arfcn]}" if out[:arfcn]
          bits << "MCC/MNC=#{out[:mcc]}/#{out[:mnc]}" if out[:mcc]
          bits << "LAC=#{out[:lac]} CI=#{out[:cell_id]}" if out[:lac]
          bits << "IMSI=#{out[:imsi]}" if out[:imsi]
          out[:summary] = "GSM #{bits.join(' ')}".strip
          out
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
              file:     'optional - .cu8/.cs16 capture (≥1.0833 Msps)'
            )

            #{self}.viterbi_decode(bits:, k: 5, g0: 0o23, g1: 0o33)

            #{self}.authors
          "
        end
      end
    end
  end
end
