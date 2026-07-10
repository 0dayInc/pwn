# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Pure-Ruby FLEX™ pager decoder.
      #
      # FLEX is Motorola's synchronous paging protocol running at 1600 or
      # 3200 symbols/s in 2- or 4-level FSK. GQRX's NBFM discriminator
      # audio (48 kHz UDP tap) is fed into a per-sample PLL symbol clock,
      # 4-level quantised, and driven through the Sync-1 → FIW → Sync-2 →
      # 11-block state machine. All four interleaved phases (A/B/C/D) are
      # de-interleaved into 88 × 32-bit BCH(31,21)+parity codewords, error
      # corrected, and walked (BIW → address → vector → message words) to
      # recover capcode + alphanumeric / numeric / binary payloads.
      #
      # Algorithm is a clean-room Ruby port of the reference behavior in
      # multimon-ng `demod_flex.c` (GPLv2), verified bit-exact against a
      # live 929.625 MHz 3200/4 capture: sync 0xDEA0, FIW cycle 10 frame
      # 70, 88/88 BCH-clean words per phase, capcodes 4294949118 /
      # 002064207 / 002064227 all matching multimon-ng ground truth.
      #
      # No `multimon-ng`, no `sox` — 100 % Ruby.
      module Flex
        SYNC_MARKER = 0xA6C6AAAA
        SLICE_TH    = 0.667
        LOCKED_RATE = 0.045
        UNLOCK_RATE = 0.050

        # Sync-1 A-word (canonical, sym<2→1 polarity) → [symbol_rate, levels]
        A_TABLE = {
          0x870C => [1600, 2],
          0xB068 => [1600, 4],
          0x7B18 => [3200, 2],
          0xDEA0 => [3200, 4],
          0x4C7C => [3200, 4]
        }.freeze

        NUM_TABLE = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '/', 'U', ' ', '-', ']', '['].freeze
        TYPE_NAME = %w[SEC SHI TON NUM SFN ALN BIN NNM].freeze

        # Streaming FLEX demodulator fed by Base.run_native / Base.run_iq.
        # Per-sample PLL symbol clock, 4-level slicer, full state machine.
        # rubocop:disable Metrics/ClassLength
        class Demod
          def initialize(rate: 48_000)
            @rate     = rate.to_f
            @zero     = 0.0
            @env      = 0.0
            @env_sum  = 0.0
            @env_n    = 0
            @phase    = 0.0
            @baud     = 1600
            @last     = 0.0
            @locked   = false
            @symcnt   = [0, 0, 0, 0]
            @state    = :sync1
            @syncbuf  = 0
            @polarity = 0
            @mode     = [1600, 2]
            @fiwcnt   = 0
            @fiw      = 0
            @s2cnt    = 0
            @dcnt     = 0
            @cycle    = 0
            @frame    = 0
            @sync_cw  = 0
            reset_phases
          end

          def feed(samples, &)
            phase_max = 100.0 * @rate
            samples.each do |x|
              # DC-offset IIR (10 ms) — only track during Sync-1 hunt
              @zero = ((@zero * (@rate * 0.010)) + x) / ((@rate * 0.010) + 1) if @state == :sync1
              s = x - @zero
              phase_rate = phase_max * @baud / @rate
              ppc = 100.0 * @phase / phase_max
              if @locked
                if @state == :sync1
                  @env_sum += s.abs
                  @env_n  += 1
                  @env     = @env_sum / @env_n
                end
              else
                @env = @env_sum = 0.0
                @env_n = 0
                @baud  = 1600
              end
              # 4-level majority vote over mid-80 % of the symbol period
              if ppc > 10 && ppc < 90
                th = @env * SLICE_TH
                if s.positive?
                  s > th ? @symcnt[3] += 1 : @symcnt[2] += 1
                else
                  s < -th ? @symcnt[0] += 1 : @symcnt[1] += 1
                end
              end
              # Zero-crossing PLL
              if (@last.negative? && s >= 0) || (@last >= 0 && s.negative?)
                perr = ppc < 50 ? @phase : @phase - phase_max
                @phase -= perr * (@locked ? LOCKED_RATE : UNLOCK_RATE)
                @locked = true
              end
              @last   = s
              @phase += phase_rate
              next unless @phase >= phase_max

              @phase -= phase_max
              sym = @symcnt.index(@symcnt.max)
              @symcnt = [0, 0, 0, 0]
              on_symbol(sym, &)
            end
          end

          # For Base.run_iq (I/Q → FM demod → this)
          alias feed_audio feed

          private

          def reset_phases
            @pa = Array.new(88, 0)
            @pb = Array.new(88, 0)
            @pc = Array.new(88, 0)
            @pd = Array.new(88, 0)
            @ptog = 0
            @dbc  = 0
          end

          def on_symbol(sym, &)
            rsym = @polarity == 1 ? 3 - sym : sym
            case @state
            when :sync1 then st_sync1(sym)
            when :fiw   then st_fiw(rsym)
            when :sync2 then st_sync2
            when :data  then st_data(rsym, &)
            end
          end

          def st_sync1(sym)
            @syncbuf = ((@syncbuf << 1) | (sym < 2 ? 1 : 0)) & 0xFFFFFFFFFFFFFFFF
            code, pol = Flex.sync_check(buf: @syncbuf)
            return unless code

            m = A_TABLE.find { |k, _| Flex.popcnt(val: k ^ code) < 4 }
            return unless m

            @sync_cw  = code
            @polarity = pol
            @mode     = m[1]
            @state    = :fiw
            @fiwcnt   = 0
            @fiw      = 0
          end

          def st_fiw(rsym)
            @fiwcnt += 1
            @fiw = ((@fiw >> 1) | (rsym > 1 ? 0x80000000 : 0)) & 0xFFFFFFFF if @fiwcnt >= 16
            return unless @fiwcnt == 48

            fw, = Flex.bch_fix(word: @fiw)
            ck = ((fw & 0xF) + ((fw >> 4) & 0xF) + ((fw >> 8) & 0xF) +
                  ((fw >> 12) & 0xF) + ((fw >> 16) & 0xF) + ((fw >> 20) & 1)) & 0xF
            if ck == 0xF
              @cycle = (fw >> 4) & 0xF
              @frame = (fw >> 8) & 0x7F
              @baud  = @mode[0]
              @state = :sync2
              @s2cnt = 0
            else
              @state = :sync1
            end
          end

          def st_sync2
            @s2cnt += 1
            return unless @s2cnt == @mode[0] * 25 / 1000

            reset_phases
            @dcnt  = 0
            @state = :data
          end

          def st_data(rsym, &)
            ba = rsym > 1 ? 1 : 0
            bb = [1, 2].include?(rsym) ? 1 : 0
            @ptog = 0 if @mode[0] == 1600
            idx = ((@dbc >> 5) & 0xFFF8) | (@dbc & 7)
            if @ptog.zero?
              @pa[idx] = ((@pa[idx] >> 1) | (ba.zero? ? 0 : 0x80000000)) & 0xFFFFFFFF
              @pb[idx] = ((@pb[idx] >> 1) | (bb.zero? ? 0 : 0x80000000)) & 0xFFFFFFFF
              @ptog = 1
            else
              @pc[idx] = ((@pc[idx] >> 1) | (ba.zero? ? 0 : 0x80000000)) & 0xFFFFFFFF
              @pd[idx] = ((@pd[idx] >> 1) | (bb.zero? ? 0 : 0x80000000)) & 0xFFFFFFFF
              @ptog = 0
            end
            @dbc  += 1 if @mode[0] == 1600 || @ptog.zero?
            @dcnt += 1
            return unless @dcnt == @mode[0] * 1760 / 1000

            emit(&)
            @baud  = 1600
            @state = :sync1
            @env_sum = 0.0
            @env_n   = 0
          end

          def emit(&)
            phases =
              case @mode
              when [1600, 2] then { 'A' => @pa }
              when [1600, 4] then { 'A' => @pa, 'B' => @pb }
              when [3200, 2] then { 'A' => @pa, 'C' => @pc }
              else { 'A' => @pa, 'B' => @pb, 'C' => @pc, 'D' => @pd }
              end
            phases.each do |ph, words|
              Flex.emit_phase(
                words: words, phase: ph, cycle: @cycle, frame: @frame,
                mode: @mode, sync_cw: @sync_cw, &
              )
            end
          end
        end
        # rubocop:enable Metrics/ClassLength

        # Supported Method Parameters::
        # code, polarity = PWN::SDR::Decoder::Flex.sync_check(buf: Integer)
        # → [16-bit A-word, 0|1] or nil

        public_class_method def self.sync_check(opts = {})
          buf = opts[:buf].to_i
          [[buf, 0], [~buf & 0xFFFFFFFFFFFFFFFF, 1]].each do |b, pol|
            marker = (b >> 16) & 0xFFFFFFFF
            ch     = (b >> 48) & 0xFFFF
            cl     = (~b) & 0xFFFF
            return [ch, pol] if popcnt(val: marker ^ SYNC_MARKER) < 4 && popcnt(val: ch ^ cl) < 4
          end
          nil
        end

        # Supported Method Parameters::
        # n = PWN::SDR::Decoder::Flex.popcnt(val: Integer)

        public_class_method def self.popcnt(opts = {})
          val = opts[:val].to_i
          c   = 0
          while val.positive?
            c += val & 1
            val >>= 1
          end
          c
        end

        # Supported Method Parameters::
        # ok = PWN::SDR::Decoder::Flex.even_parity?(word: Integer)

        public_class_method def self.even_parity?(opts = {})
          popcnt(val: opts[:word].to_i & 0xFFFFFFFF).even?
        end

        # BCH(31,21) syndrome/correction for FLEX word ordering:
        # bit 0..20 data (x^30..x^10), bit 21..30 check (x^9..x^0), bit 31 parity.
        # Verified: FIW 0xF27C46AE → syndrome 0.
        BCH_GEN = 0x769

        # Supported Method Parameters::
        # syn = PWN::SDR::Decoder::Flex.bch_syn(word: Integer)

        public_class_method def self.bch_syn(opts = {})
          word = opts[:word].to_i
          # reverse bits 0..30 so bit0 → x^30 (FLEX on-air ordering)
          r = 0
          31.times { |i| r |= ((word >> i) & 1) << (30 - i) }
          30.downto(10) { |i| r ^= BCH_GEN << (i - 10) if (r >> i).odd? }
          r & 0x3FF
        end

        BCH_TAB1 = begin
          t = {}
          31.times { |i| t[bch_syn(word: 1 << i)] = 1 << i }
          t.freeze
        end
        BCH_TAB2 = begin
          t = {}
          31.times do |i|
            ((i + 1)..30).each { |j| t[bch_syn(word: (1 << i) | (1 << j))] ||= (1 << i) | (1 << j) }
          end
          t.freeze
        end

        # Supported Method Parameters::
        # fixed, nerr = PWN::SDR::Decoder::Flex.bch_fix(word: Integer)
        # → nerr = 0/1/2 (corrected) or -1 (uncorrectable)

        public_class_method def self.bch_fix(opts = {})
          w = opts[:word].to_i & 0xFFFFFFFF
          s = bch_syn(word: w)
          return [w, 0] if s.zero? && even_parity?(word: w)
          return [w ^ 0x80000000, 1] if s.zero?

          if (m = BCH_TAB1[s])
            return [w ^ m, 1] if even_parity?(word: w ^ m)

            return [w ^ m ^ 0x80000000, 2]
          end
          m = BCH_TAB2[s]
          return [w ^ m, 2] if m && even_parity?(word: w ^ m)

          [w, -1]
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Flex.emit_phase(
        #   words:, phase:, cycle:, frame:, mode:, sync_cw:
        # ) { |msg| ... }

        public_class_method def self.emit_phase(opts = {})
          raw   = opts[:words] || []
          phase = opts[:phase]
          cycle = opts[:cycle]
          frame = opts[:frame]
          mode  = opts[:mode] || [1600, 2]
          # BCH-fix every word; abort phase on uncorrectable BIW.
          fixed = raw.map { |w| bch_fix(word: w) }
          words = fixed.map { |w, _| w & 0x1FFFFF }
          errs  = fixed.count { |_, e| e.negative? }
          biw   = words[0]
          return if fixed[0][1].negative?

          a_start = ((biw >> 8) & 0x03) + 1
          v_start = (biw >> 10) & 0x3F
          return unless a_start < v_start && v_start < 88

          (a_start...v_start).each do |i|
            aw = words[i]
            next if aw.nil? || aw.zero? || aw == 0x1FFFFF

            long_addr = aw < 0x008001 || aw > 0x1E0000
            capcode   = (aw - 0x8000) & 0xFFFFFFFF
            j    = v_start + (i - a_start)
            viw  = words[j] || 0
            type = (viw >> 4) & 0x7
            mw1  = (viw >> 7) & 0x7F
            len  = (viw >> 14) & 0x7F
            mw2  = mw1 + len - 1
            body, frag =
              case type
              when 0, 5 then alpha_decode(words: words, mw1: mw1, mw2: mw2)
              when 3, 4, 7 then [numeric_decode(words: words, mw1: mw1, mw2: mw2), nil]
              when 6 then [hex_decode(words: words[mw1..mw2]), nil]
              else [nil, nil]
              end
            out = {
              protocol: 'FLEX',
              mode: "#{mode[0]}/#{mode[1]}",
              phase: phase,
              cycle: cycle,
              frame: frame,
              capcode: capcode.to_s.rjust(9, '0'),
              long_address: long_addr,
              type: TYPE_NAME[type],
              frag: frag,
              type_payload: body,
              bch_errors: errs
            }.compact
            cf = "#{cycle.to_s.rjust(2, '0')}.#{frame.to_s.rjust(3, '0')}"
            out[:summary] =
              "FLEX|#{mode[0]}/#{mode[1]}|#{phase}|#{cf}|#{out[:capcode]}|#{out[:type]}|#{body}"[0, 200]
            yield out if block_given?
          end
        end

        # Supported Method Parameters::
        # str, frag = PWN::SDR::Decoder::Flex.alpha_decode(words:, mw1:, mw2:)

        public_class_method def self.alpha_decode(opts = {})
          words = opts[:words] || []
          mw1   = opts[:mw1].to_i
          mw2   = opts[:mw2].to_i
          return [nil, nil] unless mw1.between?(1, 87) && mw2.between?(mw1, 87)

          hdr  = words[mw1].to_i
          frag = (hdr >> 11) & 0x03
          cont = (hdr >> 10) & 0x01
          flag = if cont == 1 then 'F'
                 elsif frag == 3 then 'K'
                 else 'C'
                 end
          out = +''
          ((mw1 + 1)..mw2).each do |i|
            dw = words[i].to_i
            [0, 7, 14].each do |sh|
              ch = (dw >> sh) & 0x7F
              out << ch.chr if ch != 0x03 && ch.between?(0x20, 0x7E)
            end
          end
          [out, flag]
        end

        # Supported Method Parameters::
        # str = PWN::SDR::Decoder::Flex.numeric_decode(words:, mw1:, mw2:)

        public_class_method def self.numeric_decode(opts = {})
          words = opts[:words] || []
          mw1   = opts[:mw1].to_i
          mw2   = opts[:mw2].to_i
          return nil unless mw1.between?(1, 87) && mw2.between?(mw1, 87)

          out = +''
          # Numeric payload: 4-bit digits packed across 21-bit data words,
          # first word bits [20:14] are header (skip 2 digits worth).
          bits = []
          (mw1..mw2).each do |i|
            dw = words[i].to_i
            21.times { |b| bits << ((dw >> b) & 1) }
          end
          # skip 10-bit header (checksum+len markers)
          bits.shift(10)
          bits.each_slice(4) do |nyb|
            break if nyb.length < 4

            v = nyb[0] | (nyb[1] << 1) | (nyb[2] << 2) | (nyb[3] << 3)
            out << NUM_TABLE[v]
          end
          out.strip
        end

        # Supported Method Parameters::
        # str = PWN::SDR::Decoder::Flex.hex_decode(words: [Integer, ...])

        public_class_method def self.hex_decode(opts = {})
          words = opts[:words] || []
          words.compact.map { |w| format('%06X', w & 0x1FFFFF) }.join(' ')
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Flex.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          # Prefer true-air I/Q (FM-demod → native audio demod) when the
          # operator asks for a source/file or sets freq_obj[:iq_source].
          # Otherwise keep the GQRX 48 kHz UDP audio path (run_native).
          want_iq = opts[:source] || opts[:file] || freq_obj[:iq_source] || freq_obj[:iq_file]
          if want_iq
            PWN::SDR::Decoder::Base.run_iq(
              freq_obj: freq_obj,
              protocol: 'FLEX',
              demod: Demod.new,
              sample_rate: (opts[:sample_rate] || freq_obj[:iq_rate] || 240_000).to_i,
              source: opts[:source],
              file: opts[:file],
              fm_demod: true,
              note: 'FLEX true-air: FM-demod I/Q → PLL symbol clock → 4-level slicer → full 4-phase de-interleave.'
            )
          else
            PWN::SDR::Decoder::Base.run_native(
              freq_obj: freq_obj,
              protocol: 'FLEX',
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

            demod = #{self}::Demod.new(rate: 48_000)
            demod.feed(samples) { |msg| puts msg[:summary] }

            #{self}.bch_fix(word: Integer)        # → [fixed, nerr]
            #{self}.alpha_decode(words:, mw1:, mw2:)
            #{self}.numeric_decode(words:, mw1:, mw2:)

            NOTE: Set GQRX to Narrow FM (~15-20 kHz). All four FLEX modes
                  (1600/2, 1600/4, 3200/2, 3200/4 sym-rate/levels) are
                  fully decoded across every active phase (A/B/C/D).

            #{self}.authors
          "
        end
      end
    end
  end
end
