# frozen_string_literal: true

module PWN
  module SDR
    module Decoder
      # SDR Decoder for GSM signals.
      module GSM
        POWER_THRESHOLD = 0.1
        SLEEP_INTERVAL = 0.1
        HEADER_SIZE = 44
        BURST_DURATION_SEC = 0.000577

        # TSC 0 binary sequence (26 bits): 00100101110000101010011011
        TSC_0 = [0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1].freeze

        # Starts the live decoding thread.
        def self.start(opts = {})
          freq_obj = opts[:freq_obj]
          raise ':ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          gqrx_sock = freq_obj[:gqrx_sock]
          freq = freq_obj[:freq]
          bandwidth = freq_obj[:bandwidth].to_i
          record_path = freq_obj[:record_path]

          sleep 0.1 until File.exist?(record_path)

          header = File.binread(record_path, HEADER_SIZE)
          raise 'Invalid WAV header' unless header.start_with?('RIFF') && header.include?('WAVE')

          bytes_read = HEADER_SIZE

          puts "GSM Decoder started for freq: #{freq}, bandwidth: #{bandwidth}"

          Thread.new do
            loop do
              current_size = File.size(record_path)
              if current_size > bytes_read
                new_bytes = current_size - bytes_read
                # Ensure full I/Q pairs (8 bytes)
                new_bytes -= new_bytes % 8
                data = File.binread(record_path, new_bytes, bytes_read)
                process_chunk(
                  data: data,
                  bandwidth: bandwidth,
                  freq: freq
                )
                bytes_read = current_size
              end

              sleep SLEEP_INTERVAL
            end
          rescue StandardError => e
            puts "Decoder error: #{e.message}"
          ensure
            cleanup(record_path: record_path)
          end
        end

        # Stops the decoding thread.
        def self.stop(opts = {})
          freq_obj = opts[:freq_obj]
          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          decoder_thread = freq_obj[:decoder_thread]
          decoder_thread.kill if decoder_thread.is_a?(Thread)
        end

        class << self
          private

          def process_chunk(opts = {})
            data = opts[:data]
            bandwidth = opts[:bandwidth]
            freq = opts[:freq]
            raise ':ERROR: :data, :bandwidth, and :freq are required' unless data && bandwidth && freq

            samples = data.unpack('f< *')
            return if samples.length.odd? # Skip incomplete

            complex_samples = []
            (0...samples.length).step(2) do |i|
              complex_samples << Complex(samples[i], samples[i + 1])
            end

            window_size = [(bandwidth * BURST_DURATION_SEC).round, complex_samples.length].min
            return if window_size <= 0

            # Simplified power on sliding windows
            powers = []
            complex_samples.each_cons(window_size) do |window|
              power = window.map { |c| c.abs**2 }.sum / window_size
              powers << power
            end

            max_power = powers.max
            return unless max_power > POWER_THRESHOLD

            # Demod the entire chunk (assume burst-aligned roughly)
            bits = demod_gmsk(complex_samples)
            # Synchronize via TSC correlation
            sync_offset = find_tsc_offset(bits, TSC_0)
            return unless sync_offset >= 0

            # Extract data bits from normal burst structure
            burst_start = sync_offset - 58 # TSC starts at symbol 58 (0-index)
            return unless burst_start >= 0 && burst_start + 148 <= bits.length

            data_bits = extract_data_bits(bits, burst_start)
            puts "Burst synchronized at offset #{sync_offset} for #{freq} Hz (power: #{max_power.round(4)})"
            decode_imsi(
              data_bits: data_bits,
              freq: freq
            )
          end

          def demod_gmsk(complex_samples)
            return [] if complex_samples.length < 2

            bits = []
            (1...complex_samples.length).each do |i|
              prod = complex_samples[i] * complex_samples[i - 1].conj
              # Sign of imaginary part for quadrature differential
              bit = (prod.imag >= 0 ? 0 : 1) # Or adjust polarity
              bits << bit
            end
            bits
          end

          def find_tsc_offset(bits, tsc)
            max_corr = -1
            best_offset = -1
            tsc_length = tsc.length # 26
            (0...(bits.length - tsc_length + 1)).each do |offset|
              window = bits[offset, tsc_length]
              corr = window.zip(tsc).count { |b1, b2| b1 == b2 }
              if corr > max_corr
                max_corr = corr
                best_offset = offset
              end
            end
            # Threshold: e.g., >20 matches for good sync
            max_corr > 20 ? best_offset : -1
          end

          # Extract 114 data bits from normal burst (ignoring tails/guard)
          def extract_data_bits(bits, burst_start)
            data1_start = burst_start + 2
            data2_start = burst_start + 88 # After TSC 26 + data1 57 = 85, +3? Wait, structure: tail2(0-1), data(2-58), tsc(59-84), data(85-141), tail(142-143)
            data1 = bits[data1_start, 57]
            data2 = bits[data2_start, 57]
            data1 + data2
          end

          def decode_imsi(opts = {})
            data_bits = opts[:data_bits]
            freq = opts[:freq]
            raise ':ERROR: :data_bits and :freq are required' unless data_bits && freq

            # Simplified "IMSI extraction": Interpret first ~60 bits as packed digits (4 bits per digit, BCD-like).
            # In reality: Deinterleave (over bursts), Viterbi decode convolutional code (polys G0=10011b, G1=11011b),
            # CRC check, parse L3 message (e.g., Paging Req Type 1 has IMSI IE at specific offset, packed BCD).
            # Here: Raw data bits to 15-digit IMSI (first 60 bits -> 15 nibbles).
            return unless data_bits.length >= 60

            imsi_digits = []
            data_bits[0, 60].each_slice(4) do |nibble|
              digit = nibble.join.to_i(2)
              imsi_digits << (digit % 10) # Mod 10 for digit-like, or keep as is for hex
            end

            # Format as 3(MCC)+3(MNC)+9(MSIN)
            mcc = imsi_digits[0, 3].join
            mnc = imsi_digits[3, 3].join
            msin = imsi_digits[6, 9].join
            imsi = "#{mcc.ljust(3, '0')}#{mnc.ljust(3, '0')}#{msin.ljust(9, '0')}"

            puts "Decoded IMSI: #{imsi} at #{freq} Hz"
            # TODO: Integrate full L3 parser (e.g., from ruby-gsm gem or custom).
          end

          def cleanup(opts = {})
            record_path = opts[:record_path]
            raise ':ERROR: :record_path is required' unless record_path

            return unless File.exist?(record_path)

            File.delete(record_path)
            puts "Cleaned up recording: #{record_path}"
          end
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):
            0day Inc. <support@0dayinc.com>
          "
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            gsm_decoder_thread = PWN::SDR::Decoder::GSM.start(
              freq_obj: 'required - freq_obj returned from PWN::SDR::Receiver::GQRX.init_freq method'
            )

            # To stop the decoder thread:
            PWN::SDR::Decoder::GSM.stop(
              freq_obj: 'required - freq_obj returned from PWN::SDR::Receiver::GQRX.init_freq method'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
