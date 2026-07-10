# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # LTE (E-UTRA) true-air PSS/SSS cell search.
      #
      # I/Q resampled to 1.92 Msps (128-FFT grid), time-domain PSS
      # correlation against Zadoff-Chu roots {25,29,34} → N_ID_2 ∈ {0,1,2}
      # + half-frame timing + coarse CFO. SSS m-sequence pair 5 symbols
      # earlier → N_ID_1 ∈ 0..167 → PCI = 3·N_ID_1 + N_ID_2. All FFTs via
      # PWN::FFI::FFTW; falls back to naive DFT for small N.
      module LTE
        FS_BASE   = 1_920_000
        NFFT      = 128
        CP_NORM   = 9 # samples @ 1.92 Msps for symbols 1..6 (10 for symbol 0)
        PSS_ROOTS = { 0 => 25, 1 => 29, 2 => 34 }.freeze

        # Streaming PSS/SSS cell-search demod for Base.run_iq.
        class DemodIQ
          def initialize(rate:)
            @rate = rate.to_f
            @buf  = []
            @seen = {}
            @pss  = build_pss
          end

          def feed_iq(samples, rate: nil)
            @rate = rate.to_f if rate
            r = PWN::SDR::Decoder::DSP.resample_iq(
              iq: samples, src_rate: @rate, dst_rate: FS_BASE
            )
            @buf.concat(r)
            # need ≥ one 5 ms half-frame @ 1.92 Msps = 9600 complex
            return if @buf.length < 9600 * 2 * 2

            hit = search_pss
            if hit
              nid1 = search_sss(hit)
              pci  = nid1 ? (3 * nid1) + hit[:nid2] : nil
              key  = pci || "N2=#{hit[:nid2]}"
              unless @seen[key]
                @seen[key] = true
                yield(
                  protocol: 'LTE', event: 'cell', modulation: 'OFDMA',
                  nid2: hit[:nid2], nid1: nid1, pci: pci,
                  cfo_hz: hit[:cfo_hz], pss_peak_ratio: hit[:ratio],
                  timing_sample: hit[:pos],
                  summary: pci ? "LTE cell PCI=#{pci} (N_ID_1=#{nid1} N_ID_2=#{hit[:nid2]}) CFO=#{hit[:cfo_hz]}Hz" : "LTE PSS lock N_ID_2=#{hit[:nid2]} CFO=#{hit[:cfo_hz]}Hz (SSS pending)"
                )
              end
            end
            @buf.shift(@buf.length - (9600 * 2)) if @buf.length > 9600 * 4
          end

          private

          # Build 3 time-domain PSS templates (128 complex samples each).
          def build_pss
            PSS_ROOTS.transform_values do |root|
              zc = PWN::SDR::Decoder::DSP.zadoff_chu(root: root, n: 63)
              # Map 62 ZC values (drop k=31) onto ±31 subcarriers of a 128-FFT.
              spec = Array.new(NFFT * 2, 0.0)
              62.times do |m|
                zi = m < 31 ? m : m + 1 # skip DC element
                sc = m - 31
                k  = sc.negative? ? sc + NFFT : sc + 1 # DC left null
                spec[k * 2]       = zc[zi * 2]
                spec[(k * 2) + 1] = zc[(zi * 2) + 1]
              end
              td = PWN::FFI.available?(mod: :FFTW) ? PWN::FFI::FFTW.cfft(iq: spec, n: NFFT, sign: :backward) : PWN::SDR::Decoder::DSP.dft_naive(iq: spec, n: NFFT)
              td.flat_map { |re, im| [re, im] }
            end
          end

          def search_pss
            n = @buf.length / 2
            best = nil
            @pss.each do |nid2, tmpl|
              # sliding conj-multiply-accumulate every 4th sample for speed
              i = 0
              while i < n - NFFT
                acc_r = 0.0
                acc_i = 0.0
                NFFT.times do |j|
                  ar = @buf[(i + j) * 2]
                  ai = @buf[((i + j) * 2) + 1]
                  br = tmpl[j * 2]
                  bi = tmpl[(j * 2) + 1]
                  acc_r += (ar * br) + (ai * bi)
                  acc_i += (ai * br) - (ar * bi)
                end
                pk = (acc_r * acc_r) + (acc_i * acc_i)
                best = { nid2: nid2, pos: i, pk: pk, ang: Math.atan2(acc_i, acc_r) } if best.nil? || pk > best[:pk]
                i += 4
              end
            end
            return nil unless best

            # crude floor: mean |buf|² · NFFT
            m2 = PWN::SDR::Decoder::DSP.mag_sq(iq: @buf[0, NFFT * 8])
            floor = (m2.sum / m2.length) * NFFT
            ratio = best[:pk] / [floor, 1e-12].max
            return nil unless ratio > 6.0

            # coarse CFO from CP: correlate CP with tail of same OFDM symbol
            pos = best[:pos]
            cfo = cp_cfo(pos)
            best.merge(ratio: ratio.round(1), cfo_hz: cfo)
          end

          def cp_cfo(pos)
            return 0 if pos < CP_NORM

            a = @buf[(pos - CP_NORM) * 2, CP_NORM * 2]
            b = @buf[(pos + NFFT - CP_NORM) * 2, CP_NORM * 2]
            r = 0.0
            im = 0.0
            CP_NORM.times do |j|
              r  += (a[j * 2] * b[j * 2]) + (a[(j * 2) + 1] * b[(j * 2) + 1])
              im += (a[(j * 2) + 1] * b[j * 2]) - (a[j * 2] * b[(j * 2) + 1])
            end
            (Math.atan2(im, r) * FS_BASE / (2 * Math::PI * NFFT)).round
          end

          # SSS is one OFDM symbol before PSS. Extract 62 subcarriers,
          # brute-force N_ID_1 by testing all 168 m-sequence pairs (m0,m1).
          def search_sss(hit)
            pos = hit[:pos] - (NFFT + CP_NORM)
            return nil if pos.negative? || (pos + NFFT) * 2 > @buf.length

            sym = @buf[pos * 2, NFFT * 2]
            spec = PWN::SDR::Decoder::DSP.cfft_mag(iq: sym, n: NFFT, shift: false)
            # extract 62 SSS subcarriers (±31, skip DC)
            d = Array.new(62)
            62.times do |m|
              sc = m - 31
              k  = sc.negative? ? sc + NFFT : sc + 1
              d[m] = spec[k]
            end
            # Magnitude-only heuristic (BPSK): match interleaved even/odd
            # sub-sequences against m-sequence energy pattern per N_ID_1.
            best = nil
            168.times do |nid1|
              m0, m1 = LTE.sss_indices(nid1: nid1)
              s0 = LTE.mseq(shift: m0)
              s1 = LTE.mseq(shift: m1)
              c0 = LTE.cseq(nid2: hit[:nid2])
              score = 0.0
              31.times do |n|
                score += d[2 * n]       * s0[n] * c0[n]
                score += d[(2 * n) + 1] * s1[n] * c0[n]
              end
              best = { nid1: nid1, score: score.abs } if best.nil? || score.abs > best[:score]
            end
            best && best[:score].positive? ? best[:nid1] : nil
          end
        end

        # SSS helper: (m0, m1) pair for a given N_ID_1 per TS 36.211 §6.11.2.
        public_class_method def self.sss_indices(opts = {})
          nid1 = opts[:nid1].to_i
          qp = (nid1 / 30)
          q  = ((nid1 + (qp * (qp + 1) / 2)) / 30)
          mp = nid1 + (q * (q + 1) / 2)
          m0 = mp % 31
          m1 = (m0 + (mp / 31) + 1) % 31
          [m0, m1]
        end

        # Length-31 m-sequence x^5+x^2+1, cyclic-shifted by `shift`, as ±1.
        public_class_method def self.mseq(opts = {})
          @mseq_base ||= begin
            reg = [0, 0, 0, 0, 1]
            Array.new(31) do
              o = reg[0]
              fb = reg[0] ^ reg[3]
              reg = reg[1..] + [fb]
              1 - (2 * o)
            end
          end
          sh = opts[:shift].to_i
          Array.new(31) { |n| @mseq_base[(n + sh) % 31] }
        end

        # Scrambling sequence c0 (x^5+x^3+1) tied to N_ID_2, ±1.
        public_class_method def self.cseq(opts = {})
          @cseq_base ||= begin
            reg = [0, 0, 0, 0, 1]
            Array.new(31) do
              o = reg[0]
              fb = reg[0] ^ reg[2]
              reg = reg[1..] + [fb]
              1 - (2 * o)
            end
          end
          sh = opts[:nid2].to_i
          Array.new(31) { |n| @cseq_base[(n + sh) % 31] }
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::LTE.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 1_920_000).to_i
          PWN::SDR::Decoder::Base.run_iq(
            freq_obj: freq_obj,
            protocol: 'LTE',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate),
            note: 'OFDMA — I/Q→1.92 Msps→PSS ZC-correlate (FFTW)→N_ID_2+CFO→SSS m-seq→PCI.',
            describe: proc { |_b| { modulation: 'OFDMA', subcarrier_khz: 15 } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'LTE' }
          out[:earfcn] = ::Regexp.last_match(1) if line =~ /EARFCN[:= ]+(\d+)/i
          out[:pci]    = ::Regexp.last_match(1) if line =~ /(?:PCI|N_id_cell|Id)[:= ]+(\d{1,3})/i
          out[:prb]    = (::Regexp.last_match(1) || ::Regexp.last_match(2)) if line =~ /(?:PRB[:= ]+(\d+)|(\d+)\s*PRB)/i
          out[:rsrp]   = ::Regexp.last_match(1) if line =~ /(-?\d+(?:\.\d+)?)\s*dBm/
          out[:summary] = "LTE PCI=#{out[:pci]} EARFCN=#{out[:earfcn]} PRB=#{out[:prb]} RSRP=#{out[:rsrp]}dBm"
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
              file:     'optional - .cu8/.cs16 capture (≥1.92 Msps)'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
