# frozen_string_literal: true

require 'json'

module PWN
  module SDR
    module Decoder
      # LoRa (Semtech CSS) true-air preamble/sync-word decoder.
      #
      # I/Q resampled so fs = BW (default 125 kHz), one complex sample per
      # chirp step. For each SF ∈ 7..12: dechirp with a reference
      # down-chirp (DSP.cmul + PWN::FFI::FFTW.cfft), find ≥6 consecutive
      # symbols whose FFT-argmax bin is identical (preamble), then read
      # the two sync-word symbols and two SFD down-chirps. Emits
      # {sf:, bw_hz:, sync_word:, preamble_len:, cfo_bins:} — the same
      # metadata gr-lora / rtl-lora surface, no external binary.
      module LoRa
        DEFAULT_BW = 125_000
        SF_RANGE   = (7..12)
        # Public LoRaWAN sync = 0x34; private/Meshtastic default = 0x12.
        KNOWN_SYNC = { 0x34 => 'LoRaWAN', 0x12 => 'private/RadioLib' }.freeze

        # Streaming CSS dechirp demod for Base.run_iq.
        class DemodIQ
          def initialize(rate:, bw: DEFAULT_BW)
            @rate = rate.to_f
            @bw   = bw.to_i
            @buf  = []
            @dchirp = {}
            @seen = {}
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            r = PWN::SDR::Decoder::DSP.resample_iq(
              iq: samples, src_rate: @rate, dst_rate: @bw
            )
            @buf.concat(r)
            SF_RANGE.each { |sf| try_sf(sf, &) if block_given? }
            max = ((1 << 12) * 20) * 2
            @buf.shift(@buf.length - max) if @buf.length > max
          end

          private

          def down_chirp(sf)
            @dchirp[sf] ||= begin
              n = 1 << sf
              iq = Array.new(n * 2)
              n.times do |k|
                # base up-chirp φ(k) = π·k·(k/N − 1); down-chirp = conj.
                ph = Math::PI * k * ((k.to_f / n) - 1.0)
                iq[k * 2]       = Math.cos(ph)
                iq[(k * 2) + 1] = -Math.sin(ph)
              end
              iq
            end
          end

          def demod_symbol(iq, sf)
            n  = 1 << sf
            dc = down_chirp(sf)
            de = PWN::SDR::Decoder::DSP.cmul(a: iq, b: dc)
            mag = PWN::SDR::Decoder::DSP.cfft_mag(iq: de, n: n, shift: false)
            pk_i = mag.each_with_index.max_by(&:first).last
            [pk_i, mag[pk_i], mag.sum / mag.length]
          end

          def try_sf(sf)
            n = 1 << sf
            need = n * 12 * 2 # ≥ 8 preamble + 2 sync + 2.25 SFD
            return if @buf.length < need

            # coarse alignment: try 8 phase offsets across first symbol
            best_off = 0
            best_run = 0
            best_bin = nil
            (0...n).step([n / 8, 1].max) do |off|
              bins = []
              10.times do |s|
                seg = @buf[(off + (s * n)) * 2, n * 2]
                break if seg.nil? || seg.length < n * 2

                bins << demod_symbol(seg, sf).first
              end
              # longest run of equal bins
              run = 1
              cur = 1
              (1...bins.length).each do |i|
                if ((bins[i] - bins[i - 1]) % n).zero?
                  cur += 1
                  run = cur if cur > run
                else
                  cur = 1
                end
              end
              if run > best_run
                best_run = run
                best_off = off
                best_bin = bins.group_by { |x| x }.max_by { |_, v| v.length }&.first
              end
            end
            return unless best_run >= 6 && best_bin

            # sync symbols follow preamble; walk forward until bin changes
            i = best_off
            i += n while ((demod_symbol(@buf[i * 2, n * 2], sf).first - best_bin) % n).zero? && i < (@buf.length / 2) - (4 * n)
            s1 = demod_symbol(@buf[i * 2, n * 2], sf).first
            s2 = demod_symbol(@buf[(i + n) * 2, n * 2], sf).first
            # sync word nibble encoding (× 2^(SF-4)); recover both nibbles.
            div = 1 << (sf - 4)
            n1 = (((s1 - best_bin) % n) / div) & 0xF
            n2 = (((s2 - best_bin) % n) / div) & 0xF
            sync = (n1 << 4) | n2
            key = "SF#{sf}:#{format('%02X', sync)}"
            unless @seen[key]
              @seen[key] = true
              yield(
                protocol: 'LoRa', event: 'preamble', modulation: 'CSS',
                sf: sf, bw_hz: @bw, preamble_len: best_run,
                cfo_bins: best_bin, sync_word: format('0x%02X', sync),
                sync_name: KNOWN_SYNC[sync],
                summary: "LoRa SF#{sf}/BW#{@bw / 1000}k sync=0x#{format('%02X', sync)}#{" (#{KNOWN_SYNC[sync]})" if KNOWN_SYNC[sync]} preamble=#{best_run}"
              )
            end
            @buf.shift((i + (2 * n)) * 2)
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::LoRa.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          bw   = (opts[:bw] || freq_obj[:lora_bw] || DEFAULT_BW).to_i
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || (bw * 4)).to_i
          PWN::SDR::Decoder::Base.run_iq(
            freq_obj: freq_obj,
            protocol: 'LoRa',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate, bw: bw),
            note: 'CSS 125–500 kHz — I/Q→resample_iq(fs=BW)→dechirp+FFTW per SF→preamble/sync-word.',
            describe: proc { |b| { modulation: 'CSS', bw_khz_assumed: bw / 1000, sf_estimate: b[:sf] } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          h = begin
            JSON.parse(line, symbolize_names: true)
          rescue StandardError
            { unparsed: line }
          end
          out = { protocol: 'LoRa' }.merge(h)
          bits = []
          bits << "SF#{out[:sf]}" if out[:sf]
          bits << "BW#{out[:bw]}" if out[:bw]
          bits << "sync=#{out[:sync_word]}" if out[:sync_word]
          bits << out[:payload].to_s[0, 40] if out[:payload]
          out[:summary] = bits.empty? ? line[0, 120] : bits.join(' ')
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
              file:     'optional - .cu8/.cs16 capture',
              bw:       'optional - LoRa BW Hz (default 125000)'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
