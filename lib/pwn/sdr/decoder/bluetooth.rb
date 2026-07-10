# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # Bluetooth LE (& BR/EDR sync-trailer) true-air decoder.
      #
      # I/Q → PWN::FFI::Liquid.gmsk_demod (or DSP.fm_demod_iq→NRZ) at
      # 1 Mbit/s → hunt LSB-first Access Address (adv = 0x8E89BED6) →
      # dewhiten (7-bit LFSR seeded ch|0x40) → PDU header (type/len) →
      # AdvA (6 bytes) → CRC-24 (poly 0x65B, init 0x555555). Emits per-PDU
      # {access_addr:, pdu_type:, adv_addr:, crc_ok:} — ubertooth-parity
      # advertising sniff with no external binary.
      module Bluetooth
        BLE_ADV_AA   = 0x8E89BED6
        BLE_CRC_POLY = 0x65B
        BLE_CRC_INIT = 0x555555
        BLE_PDU_TYPE = {
          0 => 'ADV_IND', 1 => 'ADV_DIRECT_IND', 2 => 'ADV_NONCONN_IND',
          3 => 'SCAN_REQ', 4 => 'SCAN_RSP', 5 => 'CONNECT_IND',
          6 => 'ADV_SCAN_IND', 7 => 'ADV_EXT_IND'
        }.freeze
        BLE_ADV_CHANNELS = { 37 => 2_402_000_000, 38 => 2_426_000_000, 39 => 2_480_000_000 }.freeze
        # BR/EDR: 64-bit sync word derived from LAP; general-inquiry LAP=0x9E8B33.
        GIAC_LAP = 0x9E8B33

        # Streaming BLE GFSK demod for Base.run_iq — I/Q → advertising PDUs.
        class DemodIQ
          BAUD = 1_000_000

          def initialize(rate:, channel: 37, ble: true)
            @rate    = rate.to_f
            @channel = channel
            @ble     = ble
            @bits    = []
            @seen    = {}
          end

          def feed_iq(samples, rate: nil, &)
            @rate = rate.to_f if rate
            # Try both polarities — GFSK sign depends on tuner spectral inversion.
            new_bits = PWN::SDR::Decoder::DSP.gfsk_slice(
              iq: samples, rate: @rate, baud: BAUD, bt: 0.5
            )
            @bits.concat(new_bits)
            scan(&) if block_given?
            @bits.shift(@bits.length - 4096) if @bits.length > 65_536
          end

          private

          # 32-bit AA is transmitted LSB-first on the air.
          AA_BITS = Array.new(32) { |i| (BLE_ADV_AA >> i) & 1 }
          AA_INV  = AA_BITS.map { |b| b ^ 1 }.freeze

          def scan
            i = 0
            while i <= @bits.length - (32 + 16 + 24)
              inv = nil
              inv = false if match_at?(i, AA_BITS)
              inv = true  if inv.nil? && match_at?(i, AA_INV)
              unless inv.nil?
                pdu = decode_pdu(@bits[(i + 32)..], inv)
                if pdu
                  key = "#{pdu[:adv_addr]}:#{pdu[:pdu_type]}:#{pdu[:crc_rx]}"
                  unless @seen[key]
                    @seen[key] = true
                    @seen.shift if @seen.length > 256
                    yield pdu
                  end
                  i += 32 + ((2 + pdu[:length].to_i + 3) * 8)
                  next
                end
              end
              i += 1
            end
            @bits.shift([i - 32, 0].max) if i > 32
          end

          def match_at?(idx, pat, max_err: 2)
            err = 0
            j = 0
            while j < pat.length
              err += 1 if @bits[idx + j] != pat[j]
              return false if err > max_err

              j += 1
            end
            true
          end

          def decode_pdu(stream, inv)
            stream = stream.map { |b| b ^ 1 } if inv
            hdr_b  = PWN::SDR::Decoder::DSP.bytes_from_bits(bits: stream[0, 16], lsb_first: true)
            hdr    = PWN::SDR::Decoder::DSP.whiten_lfsr(
              bytes: hdr_b, poly: 0x11, init: (@channel & 0x3F) | 0x40, width: 7
            )
            return nil if hdr.length < 2

            ptype = hdr[0] & 0x0F
            len   = hdr[1] & 0xFF
            return nil if len > 255 || (2 + len + 3) * 8 > stream.length

            body_b = PWN::SDR::Decoder::DSP.bytes_from_bits(
              bits: stream[0, (2 + len + 3) * 8], lsb_first: true
            )
            dewh = PWN::SDR::Decoder::DSP.whiten_lfsr(
              bytes: body_b, poly: 0x11, init: (@channel & 0x3F) | 0x40, width: 7
            )
            payload = dewh[2, len] || []
            crc_rx  = dewh[2 + len, 3] || []
            crc_ok  = Bluetooth.ble_crc24(bytes: dewh[0, 2 + len]) ==
                      (crc_rx[0].to_i | (crc_rx[1].to_i << 8) | (crc_rx[2].to_i << 16))
            adv_addr = payload.length >= 6 ? payload[0, 6].reverse.map { |b| format('%02X', b) }.join(':') : nil
            {
              protocol: @ble ? 'BLE' : 'BT-BR/EDR', event: 'pdu',
              modulation: 'GFSK', channel: @channel,
              access_addr: format('%08X', BLE_ADV_AA),
              pdu_type: BLE_PDU_TYPE[ptype] || ptype,
              tx_add: (hdr[0] >> 6) & 1, rx_add: (hdr[0] >> 7) & 1,
              length: len, adv_addr: adv_addr, crc_ok: crc_ok,
              crc_rx: crc_rx.map { |b| format('%02X', b) }.join,
              payload_hex: payload.map { |b| format('%02X', b) }.join,
              summary: "BLE #{BLE_PDU_TYPE[ptype] || ptype} AdvA=#{adv_addr} len=#{len} ch=#{@channel} crc=#{crc_ok ? 'OK' : 'BAD'}"
            }
          end
        end

        # Supported Method Parameters::
        # crc = PWN::SDR::Decoder::Bluetooth.ble_crc24(bytes: Array<Integer>)
        # BLE CRC-24 (LSB-first LFSR, poly 0x65B, init 0x555555).

        public_class_method def self.ble_crc24(opts = {})
          bytes = opts[:bytes] || []
          reg = BLE_CRC_INIT
          bytes.each do |byte|
            8.times do |i|
              b = (byte >> i) & 1
              fb = (reg ^ b) & 1
              reg >>= 1
              reg ^= (BLE_CRC_POLY << 0) | 0xB4C000 if fb == 1
              reg &= 0xFFFFFF
            end
          end
          # Register holds CRC LSB-first — return as-is (matched LSB-first on air)
          reg
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Bluetooth.decode(
        #   freq_obj: 'required - freq_obj returned from PWN::SDR::GQRX.init_freq'
        # )

        public_class_method def self.decode(opts = {})
          freq_obj = opts[:freq_obj]
          hz  = PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          ble = freq_obj[:ble] || freq_obj[:mode].to_s.casecmp('ble').zero? || true
          # Nearest BLE advertising channel unless caller forces one.
          ch = opts[:channel] ||
               BLE_ADV_CHANNELS.min_by { |_, f| (f - hz).abs }&.first || 37
          rate = (opts[:sample_rate] || freq_obj[:iq_rate] || 4_000_000).to_i
          PWN::SDR::Decoder::Base.run_iq(
            freq_obj: freq_obj,
            protocol: ble ? 'BLE' : 'BT-BR/EDR',
            sample_rate: rate,
            source: opts[:source],
            file: opts[:file],
            demod: DemodIQ.new(rate: rate, channel: ch, ble: ble),
            note: '1 Mbit/s GFSK — I/Q→gmskdem→AA 0x8E89BED6→dewhiten→PDU/AdvA/CRC-24.',
            describe: proc { |b| { modulation: 'GFSK', channel: ch, hop_slots: (b[:duration_ms] / 0.625).round } }
          )
        end

        public_class_method def self.parse_line(opts = {})
          line = opts[:line].to_s
          out  = { protocol: 'Bluetooth' }
          out[:lap]      = ::Regexp.last_match(1) if line =~ /LAP[=: ]([0-9a-fA-F]{6})/
          out[:uap]      = ::Regexp.last_match(1) if line =~ /UAP[=: ]([0-9a-fA-F]{2})/
          out[:bd_addr]  = ::Regexp.last_match(1) if line =~ /(?:AdvA|BD_ADDR)[=: ]([0-9a-fA-F:]{12,17})/
          out[:pdu_type] = ::Regexp.last_match(1) if line =~ /\b(ADV_\w+|SCAN_\w+|CONNECT_REQ)\b/
          out[:channel]  = ::Regexp.last_match(1) if line =~ /ch[=: ]?(\d{1,2})\b/i
          out[:rssi]     = ::Regexp.last_match(1) if line =~ /rssi[=: ]?(-?\d+)/i
          out[:summary]  = "BT #{out.values_at(:pdu_type, :bd_addr, :lap).compact.join(' ')}".strip
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
              file:     'optional - .cu8/.cs16 capture (≥2 Msps)',
              channel:  'optional - BLE adv channel 37|38|39 (default nearest to freq)'
            )

            #{self}.ble_crc24(bytes: [..])

            #{self}.authors
          "
        end
      end
    end
  end
end
