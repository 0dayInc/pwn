# frozen_string_literal: true

require 'json'
require 'tty-spinner'
require 'tty-screen'
require 'io/wait'

module PWN
  module SDR
    module Decoder
      # Shared, 100 % Ruby-native pipeline plumbing for every
      # PWN::SDR::Decoder::* module.
      #
      # Three entry points, none of which shell out to any external binary:
      #
      #   run_native  — Bind the GQRX 48 kHz s16le mono UDP audio tap, unpack
      #                 the samples with PWN::SDR::Decoder::DSP, hand each
      #                 chunk to a caller-supplied `demod:` object that
      #                 responds to `#feed(samples, &emit)`. Every Hash the
      #                 demodulator emits is merged with freq_obj, JSON-
      #                 pretty-printed, JSONL-logged, and shown on the
      #                 spinner. [ENTER] stops cleanly.
      #
      #   run_iq      — True-air path. Opens a real SDR front-end via
      #                 PWN::FFI::{RTLSdr,HackRF,AdalmPluto,SoapySDR} (or
      #                 reads a capture file), streams interleaved I/Q into
      #                 a demod that responds to `#feed_iq(iq, rate:, &emit)`
      #                 (or `#feed` after optional FM-demod). Falls back to
      #                 run_detector when no hardware/file source is present
      #                 so the operator still gets structured output.
      #
      #   run_detector — For protocols whose bit-rate/bandwidth cannot be
      #                 recovered from a 48 kHz demodulated-audio tap (GSM,
      #                 LTE, ADS-B, WiFi, LoRa, GPS, DECT, ZigBee, Bluetooth,
      #                 Iridium, P25, ISM/RFID …). Pure-Ruby energy / burst
      #                 characterizer: polls GQRX `l STRENGTH`, and (when the
      #                 UDP tap is enabled) computes RMS-dBFS on the audio.
      #                 Emits `{event: 'burst', dbfs:, duration_ms:}` frames
      #                 whenever the signal crosses an adaptive threshold, so
      #                 the operator still gets structured, logged intel
      #                 without ANY external decoding binary.
      module Base
        # Supported Method Parameters::
        # PWN::SDR::Decoder::Base.run_native(
        #   freq_obj: 'required - freq_obj Hash from PWN::SDR::GQRX.init_freq',
        #   protocol: 'required - short name for banner / log filename',
        #   demod:    'required - object responding to #feed(samples,&emit)',
        #   rate:     'optional - assumed UDP sample rate (default 48000)'
        # )

        public_class_method def self.run_native(opts = {})
          freq_obj = opts[:freq_obj]
          protocol = opts[:protocol] || 'SIGNAL'
          demod    = opts[:demod]
          rate     = (opts[:rate] || 48_000).to_i

          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)
          raise 'ERROR: :demod must respond to #feed' unless demod.respond_to?(:feed)

          udp_ip   = freq_obj[:udp_ip]   || '127.0.0.1'
          udp_port = freq_obj[:udp_port] || 7355
          log_obj  = strip_freq_obj(freq_obj: freq_obj)

          puts JSON.pretty_generate(log_obj)
          puts "\n*** #{protocol} Decoder (ruby-native) ***"
          puts 'Press [ENTER] to continue to next frequency...'

          spinner, max_len = build_spinner(
            banner: "INFO: Decoding #{protocol} on udp://#{udp_ip}:#{udp_port} @ #{rate} Hz (native)"
          )
          log_file = log_path(protocol: protocol)

          udp_listener = PWN::SDR::GQRX.listen_udp(udp_ip: udp_ip, udp_port: udp_port)
          audio_q      = Queue.new
          current_line = 'Waiting for data frames...'

          receiver_thread = Thread.new do
            loop do
              data, = udp_listener.recv(4096)
              audio_q.push(data) if data.to_s.bytesize.positive?
            end
          rescue IOError, Errno::ECONNRESET, Errno::EBADF
            nil
          end

          decoder_thread = Thread.new do
            emit = proc do |msg|
              next unless msg.is_a?(Hash)

              final = log_obj.merge(decoded_at: Time.now.strftime('%Y-%m-%d %H:%M:%S%z')).merge(msg)
              spinner.stop
              puts JSON.pretty_generate(final)
              spinner.auto_spin
              File.open(log_file, 'a') { |f| f.puts("#{JSON.generate(final)},") }
              disp = (msg[:summary] || msg[:raw] || msg.values.compact.first).to_s
              current_line = disp[0...max_len]
            end
            loop do
              raw = audio_q.pop
              samples = PWN::SDR::Decoder::DSP.unpack_s16le(data: raw)
              demod.feed(samples, &emit)
            end
          rescue StandardError => e
            current_line = "demod error: #{e.class}: #{e.message}"
          end

          wait_for_enter(spinner: spinner, title_ref: -> { current_line })
          spinner.success('Decoding stopped')
        rescue StandardError => e
          spinner&.error("Decoding failed: #{e.message}") if defined?(spinner)
          raise
        ensure
          [receiver_thread, decoder_thread].compact.each { |t| t.kill if t&.alive? }
          PWN::SDR::GQRX.disconnect_udp(udp_listener: udp_listener) if udp_listener
          spinner&.stop if defined?(spinner)
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Base.run_detector(
        #   freq_obj:  'required - freq_obj Hash from PWN::SDR::GQRX.init_freq',
        #   protocol:  'required - short name for banner / log filename',
        #   note:      'optional - one-line explanation shown once',
        #   threshold: 'optional - dBFS above rolling floor to call a burst (default 8.0)',
        #   describe:  'optional - Proc.new { |burst_hash| Hash } extra fields'
        # )

        public_class_method def self.run_detector(opts = {})
          freq_obj  = opts[:freq_obj]
          protocol  = opts[:protocol] || 'SIGNAL'
          note      = opts[:note]
          threshold = (opts[:threshold] || 8.0).to_f
          describe  = opts[:describe]

          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)

          gqrx_sock = freq_obj[:gqrx_sock]
          udp_ip    = freq_obj[:udp_ip]   || '127.0.0.1'
          udp_port  = freq_obj[:udp_port] || 7355
          log_obj   = strip_freq_obj(freq_obj: freq_obj)

          puts JSON.pretty_generate(log_obj)
          puts "\n*** #{protocol} Signal Detector (ruby-native) ***"
          puts "[i] #{note}" if note
          puts 'Press [ENTER] to continue to next frequency...'

          spinner, max_len = build_spinner(
            banner: "INFO: Characterizing #{protocol} activity on #{log_obj[:freq] || "udp://#{udp_ip}:#{udp_port}"} (native)"
          )
          log_file = log_path(protocol: protocol)

          udp_listener = begin
            PWN::SDR::GQRX.listen_udp(udp_ip: udp_ip, udp_port: udp_port)
          rescue StandardError
            nil
          end

          current_line = 'Establishing noise floor...'
          floor    = nil
          in_burst = false
          burst_t0 = nil
          peak     = -200.0
          burst_n  = 0

          detector_thread = Thread.new do
            emit = proc do |msg|
              final = log_obj.merge(decoded_at: Time.now.strftime('%Y-%m-%d %H:%M:%S%z')).merge(msg)
              spinner.stop
              puts JSON.pretty_generate(final)
              spinner.auto_spin
              File.open(log_file, 'a') { |f| f.puts("#{JSON.generate(final)},") }
              current_line = (msg[:summary] || '').to_s[0...max_len]
            end

            loop do
              lvl = read_level(gqrx_sock: gqrx_sock, udp_listener: udp_listener)
              if lvl
                floor = floor.nil? ? lvl : ((floor * 0.98) + (lvl * 0.02))
                delta = lvl - floor
                if delta >= threshold
                  unless in_burst
                    in_burst = true
                    burst_t0 = Time.now
                    peak = lvl
                  end
                  peak = lvl if lvl > peak
                  current_line = format('%<p>s BURST %<l>+.1f dBFS (Δ%<d>+.1f, floor %<f>+.1f)', p: protocol, l: lvl, d: delta, f: floor)[0...max_len]
                elsif in_burst
                  in_burst = false
                  burst_n += 1
                  dur_ms = ((Time.now - burst_t0) * 1000).round
                  msg = {
                    protocol: protocol, event: 'burst', burst_no: burst_n,
                    peak_dbfs: peak.round(1), floor_dbfs: floor.round(1),
                    delta_db: (peak - floor).round(1), duration_ms: dur_ms,
                    summary: format('%<p>s burst #%<n>d peak=%<pk>+.1f dBFS Δ=%<d>.1f dB dur=%<ms>d ms', p: protocol, n: burst_n, pk: peak, d: peak - floor, ms: dur_ms)
                  }
                  msg.merge!(describe.call(msg)) if describe.respond_to?(:call)
                  emit.call(msg)
                else
                  current_line = format('%<p>s idle %<l>+.1f dBFS (floor %<f>+.1f, Δ%<d>+.1f)', p: protocol, l: lvl, f: floor, d: delta)[0...max_len]
                end
              end
              sleep(udp_listener ? 0 : 0.1)
            end
          rescue StandardError => e
            current_line = "detector error: #{e.class}: #{e.message}"
          end

          wait_for_enter(spinner: spinner, title_ref: -> { current_line })
          spinner.success('Detector stopped')
        rescue StandardError => e
          spinner&.error("Detector failed: #{e.message}") if defined?(spinner)
          raise
        ensure
          detector_thread&.kill if defined?(detector_thread) && detector_thread&.alive?
          PWN::SDR::GQRX.disconnect_udp(udp_listener: udp_listener) if udp_listener
          spinner&.stop if defined?(spinner)
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Base.match_line?(line: str, matcher: Regexp|String|Array)

        public_class_method def self.match_line?(opts = {})
          line    = opts[:line].to_s
          matcher = opts[:matcher]
          case matcher
          when Regexp then line.match?(matcher)
          when String then line.start_with?(matcher)
          when Array  then matcher.any? { |m| match_line?(line: line, matcher: m) }
          else true
          end
        end

        # ---------------------------------------------------------------
        # Internals
        # ---------------------------------------------------------------

        # Supported Method Parameters::
        # h = PWN::SDR::Decoder::Base.strip_freq_obj(freq_obj: {...})

        private_class_method def self.strip_freq_obj(opts = {})
          fo = opts[:freq_obj].dup
          fo.delete(:gqrx_sock)
          fo.delete(:decoder_module)
          fo
        end

        # Supported Method Parameters::
        # spinner, max_len = PWN::SDR::Decoder::Base.build_spinner(banner: '...')

        private_class_method def self.build_spinner(opts = {})
          banner = opts[:banner].to_s
          spinner = TTY::Spinner.new('[:spinner] :status', format: :arrow_pulse, clear: true, hide_cursor: true)
          overhead = 12
          max_len  = [TTY::Screen.width - overhead, 50].max
          banner   = banner[0...max_len] if banner.length > max_len
          spinner.update(status: banner)
          spinner.auto_spin
          [spinner, max_len]
        end

        # Supported Method Parameters::
        # path = PWN::SDR::Decoder::Base.log_path(protocol: 'POCSAG')

        private_class_method def self.log_path(opts = {})
          protocol = opts[:protocol].to_s
          "/tmp/#{protocol.downcase.gsub(/[^a-z0-9]+/, '_')}_decoder_#{Time.now.strftime('%Y%m%d')}.log"
        end

        # Supported Method Parameters::
        # lvl = PWN::SDR::Decoder::Base.read_level(gqrx_sock:, udp_listener:)

        private_class_method def self.read_level(opts = {})
          gqrx_sock    = opts[:gqrx_sock]
          udp_listener = opts[:udp_listener]
          if udp_listener
            begin
              data, = udp_listener.recv(4096)
              return PWN::SDR::Decoder::DSP.rms_dbfs(samples: PWN::SDR::Decoder::DSP.unpack_s16le(data: data)) if data.to_s.bytesize.positive?
            rescue IOError, Errno::ECONNRESET, Errno::EBADF
              nil
            end
          end
          return nil unless gqrx_sock

          PWN::SDR::GQRX.cmd(gqrx_sock: gqrx_sock, cmd: 'l STRENGTH').to_f
        rescue StandardError
          nil
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Base.wait_for_enter(spinner:, title_ref:)

        private_class_method def self.wait_for_enter(opts = {})
          spinner   = opts[:spinner]
          title_ref = opts[:title_ref]
          loop do
            spinner.update(status: title_ref.call)
            next unless $stdin.wait_readable(0)

            begin
              char = $stdin.read_nonblock(1)
              next unless char == "\n"

              puts "\n[!] ENTER pressed → stopping..."
              break
            rescue IO::WaitReadable, EOFError
              nil
            end
          end
        end

        # Supported Method Parameters::
        # src = PWN::SDR::Decoder::Base.resolve_iq_source(
        #   freq_obj:    'required',
        #   source:      'optional - :auto|:rtlsdr|:hackrf|:adalm_pluto|:soapy|:file',
        #   sample_rate: 'optional - desired rate Hz',
        #   file:        'optional - path to .cu8/.cs16/.iq capture'
        # )
        # Returns { kind:, rate_hz:, ... } handle, or nil if nothing available.

        public_class_method def self.resolve_iq_source(opts = {})
          freq_obj = opts[:freq_obj] || {}
          want     = (opts[:source] || freq_obj[:iq_source] || :auto).to_s.downcase.to_sym
          rate     = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_048_000).to_i
          file     = opts[:file] || freq_obj[:iq_file]
          freq_hz  = begin
            PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          rescue StandardError
            freq_obj[:freq].to_i
          end

          try = lambda do |kind|
            case kind
            when :file
              return nil if file.to_s.empty? || !File.file?(file.to_s)

              fmt = opts[:iq_format] || freq_obj[:iq_format]
              fmt ||= file.to_s.end_with?('.cs16', '.sc16') ? :cs16 : :cu8
              { kind: :file, path: file.to_s, format: fmt.to_sym, rate_hz: rate, freq_hz: freq_hz }
            when :rtlsdr
              return nil unless PWN::FFI.available?(mod: :RTLSdr)
              return nil if PWN::FFI::RTLSdr.list_devices.empty?

              dev = PWN::FFI::RTLSdr.open(index: (opts[:index] || 0).to_i)
              PWN::FFI::RTLSdr.configure(
                device: dev, freq_hz: freq_hz, rate_hz: rate,
                gain_db: opts[:gain_db] || freq_obj[:gain_db],
                ppm: opts[:ppm] || freq_obj[:ppm] || 0
              )
              { kind: :rtlsdr, device: dev, rate_hz: rate, freq_hz: freq_hz, format: :cu8 }
            when :hackrf
              return nil unless PWN::FFI.available?(mod: :HackRF)

              dev = PWN::FFI::HackRF.open(serial: opts[:serial])
              PWN::FFI::HackRF.configure(
                device: dev, freq_hz: freq_hz, rate_hz: rate,
                lna_gain: opts[:lna_gain] || 16,
                vga_gain: opts[:vga_gain] || 20,
                amp: opts[:amp]
              )
              rx = PWN::FFI::HackRF.start_rx(device: dev)
              { kind: :hackrf, device: dev, handle: rx, rate_hz: rate, freq_hz: freq_hz, format: :cs8 }
            when :adalm_pluto, :pluto
              return nil unless PWN::FFI.available?(mod: :AdalmPluto)

              ctx = PWN::FFI::AdalmPluto.open(uri: opts[:uri] || freq_obj[:pluto_uri])
              PWN::FFI::AdalmPluto.configure(
                context: ctx, freq_hz: freq_hz, rate_hz: rate,
                gain_db: opts[:gain_db] || freq_obj[:gain_db]
              )
              handle = PWN::FFI::AdalmPluto.start_rx(
                context: ctx,
                samples: (opts[:chunk_samples] || 262_144).to_i
              )
              { kind: :adalm_pluto, context: ctx, handle: handle, rate_hz: rate, freq_hz: freq_hz, format: :cs16 }
            when :soapy
              return nil unless PWN::FFI.available?(mod: :SoapySDR)
              return nil if PWN::FFI::SoapySDR.list_devices.empty?

              h = PWN::FFI::SoapySDR.open(
                args: opts[:soapy_args] || freq_obj[:soapy_args],
                channel: opts[:channel] || 0
              )
              PWN::FFI::SoapySDR.configure(
                handle: h, freq_hz: freq_hz, rate_hz: rate,
                gain_db: opts[:gain_db] || freq_obj[:gain_db]
              )
              PWN::FFI::SoapySDR.start_rx(
                handle: h,
                samples: (opts[:chunk_samples] || 65_536).to_i
              )
              { kind: :soapy, handle: h, rate_hz: rate, freq_hz: freq_hz, format: :cs16, streaming: true }
            end
          rescue StandardError
            nil
          end

          order =
            case want
            when :auto
              %i[file rtlsdr adalm_pluto hackrf soapy]
            else
              [want]
            end
          order.each do |k|
            h = try.call(k)
            return h if h
          end
          nil
        end

        # Supported Method Parameters::
        # chunk = PWN::SDR::Decoder::Base.read_iq_chunk(source: handle, bytes: 262_144)
        # Returns raw binary String in the source's native format, or nil on EOF.

        public_class_method def self.read_iq_chunk(opts = {})
          src   = opts[:source]
          bytes = (opts[:bytes] || 262_144).to_i
          raise 'ERROR: :source required' unless src.is_a?(Hash)

          case src[:kind]
          when :file
            src[:io] ||= File.open(src[:path], 'rb')
            data = src[:io].read(bytes)
            data.to_s.empty? ? nil : data
          when :rtlsdr
            PWN::FFI::RTLSdr.read_sync(device: src[:device], bytes: bytes)
          when :adalm_pluto
            PWN::FFI::AdalmPluto.read_sync(handle: src[:handle])
          when :hackrf
            PWN::FFI::HackRF.read_sync(handle: src[:handle])
          when :soapy
            PWN::FFI::SoapySDR.read_sync(handle: src[:handle])
          end
        rescue StandardError
          nil
        end

        # Supported Method Parameters::
        # iq = PWN::SDR::Decoder::Base.unpack_iq(source: handle, data: raw_string)
        # → interleaved Array<Float> [I0,Q0,…]

        public_class_method def self.unpack_iq(opts = {})
          src  = opts[:source] || {}
          data = opts[:data].to_s
          case (src[:format] || :cu8).to_sym
          when :cs16 then PWN::SDR::Decoder::DSP.unpack_cs16le(data: data)
          when :cs8
            # HackRF signed 8-bit interleaved I/Q
            data.unpack('c*').map { |v| v / 128.0 }
          else # :cu8 / unknown
            PWN::SDR::Decoder::DSP.unpack_cu8(data: data)
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Base.close_iq_source(source: handle)

        public_class_method def self.close_iq_source(opts = {})
          src = opts[:source]
          return unless src.is_a?(Hash)

          case src[:kind]
          when :file
            src[:io]&.close
          when :rtlsdr
            PWN::FFI::RTLSdr.close(device: src[:device]) if src[:device]
          when :adalm_pluto
            PWN::FFI::AdalmPluto.stop_rx(handle: src[:handle]) if src[:handle]
            PWN::FFI::AdalmPluto.close(context: src[:context]) if src[:context]
          when :hackrf
            PWN::FFI::HackRF.stop_rx(handle: src[:handle]) if src[:handle]
            PWN::FFI::HackRF.close(device: src[:device]) if src[:device]
          when :soapy
            PWN::FFI::SoapySDR.close(handle: src[:handle]) if src[:handle]
          end
        rescue StandardError
          nil
        ensure
          src[:io] = nil if src.is_a?(Hash)
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Base.run_iq(
        #   freq_obj:    'required - freq_obj Hash',
        #   protocol:    'required - short name',
        #   demod:       'required - object with #feed_iq(iq, rate:, &emit)
        #                            OR #feed(samples, &emit) when fm_demod:true',
        #   sample_rate: 'optional - Hz (default 2_048_000)',
        #   source:      'optional - :auto|:rtlsdr|:hackrf|:adalm_pluto|:soapy|:file',
        #   file:        'optional - path to capture',
        #   fm_demod:    'optional - FM-demod I/Q→audio then #feed (default false)',
        #   chunk_bytes: 'optional - bytes per read (default 262144)',
        #   fallback:    'optional - :detector|:raise|:silent (default :detector)',
        #   note:        'optional - shown once when falling back',
        #   describe:    'optional - Proc for detector fallback'
        # )

        public_class_method def self.run_iq(opts = {})
          freq_obj = opts[:freq_obj]
          protocol = opts[:protocol] || 'SIGNAL'
          demod    = opts[:demod]
          rate     = (opts[:sample_rate] || 2_048_000).to_i
          fm_demod = opts[:fm_demod] ? true : false
          chunk_b  = (opts[:chunk_bytes] || 262_144).to_i
          fallback = (opts[:fallback] || :detector).to_sym

          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)
          raise 'ERROR: :demod required' if demod.nil?

          src = resolve_iq_source(
            freq_obj: freq_obj,
            source: opts[:source],
            sample_rate: rate,
            file: opts[:file],
            gain_db: opts[:gain_db],
            uri: opts[:uri],
            index: opts[:index],
            chunk_samples: chunk_b / 4
          )

          unless src && src[:streaming] != false
            case fallback
            when :raise
              raise 'ERROR: no I/Q source available (RTL-SDR / ADALM-Pluto / HackRF / SoapySDR / file)'
            when :silent
              return nil
            else
              return run_detector(
                freq_obj: freq_obj,
                protocol: protocol,
                note: opts[:note] || "No I/Q source — falling back to energy detector. Plug in RTL-SDR/HackRF/Pluto/Soapy or pass iq_file: for true-air decode of #{protocol}.",
                threshold: opts[:threshold],
                describe: opts[:describe]
              )
            end
          end

          rate = src[:rate_hz] if src[:rate_hz]
          log_obj = strip_freq_obj(freq_obj: freq_obj).merge(
            iq_source: src[:kind], iq_rate: rate, iq_format: src[:format]
          )

          puts JSON.pretty_generate(log_obj)
          puts "\n*** #{protocol} Decoder (true-air I/Q via #{src[:kind]}) ***"
          puts 'Press [ENTER] to continue to next frequency...'

          spinner, max_len = build_spinner(
            banner: "INFO: Air-decoding #{protocol} @ #{rate} Hz from #{src[:kind]}"
          )
          log_file = log_path(protocol: protocol)
          current_line = "Streaming I/Q from #{src[:kind]}..."
          iq_q = Queue.new
          stop = false

          reader_thread = Thread.new do
            loop do
              break if stop

              raw = read_iq_chunk(source: src, bytes: chunk_b)
              break if raw.nil?

              iq_q.push(raw) if raw.bytesize.positive?
            end
          rescue StandardError => e
            current_line = "iq-reader: #{e.class}: #{e.message}"
          ensure
            iq_q.push(:eof)
          end

          decoder_thread = Thread.new do
            emit = proc do |msg|
              next unless msg.is_a?(Hash)

              final = log_obj.merge(decoded_at: Time.now.strftime('%Y-%m-%d %H:%M:%S%z')).merge(msg)
              spinner.stop
              puts JSON.pretty_generate(final)
              spinner.auto_spin
              File.open(log_file, 'a') { |f| f.puts("#{JSON.generate(final)},") }
              disp = (msg[:summary] || msg[:raw] || msg.values.compact.first).to_s
              current_line = disp[0...max_len]
            end

            loop do
              raw = iq_q.pop
              break if raw == :eof || stop
              next unless raw.is_a?(String)

              iq = unpack_iq(source: src, data: raw)
              if fm_demod && demod.respond_to?(:feed)
                audio = PWN::SDR::Decoder::DSP.fm_demod_iq(iq: iq)
                demod.feed(audio, &emit)
              elsif demod.respond_to?(:feed_iq)
                demod.feed_iq(iq, rate: rate, &emit)
              elsif demod.respond_to?(:feed)
                # magnitude envelope as last-resort real signal
                demod.feed(PWN::SDR::Decoder::DSP.mag_sq(iq: iq).map { |v| Math.sqrt(v) }, &emit)
              else
                raise 'ERROR: demod must respond to #feed_iq or #feed'
              end
            end
          rescue StandardError => e
            current_line = "iq-demod: #{e.class}: #{e.message}"
          end

          wait_for_enter(spinner: spinner, title_ref: -> { current_line })
          stop = true
          spinner.success('Air-decode stopped')
        rescue StandardError => e
          spinner&.error("Air-decode failed: #{e.message}") if defined?(spinner)
          raise
        ensure
          stop = true if defined?(stop)
          [reader_thread, decoder_thread].compact.each { |th| th.kill if th&.alive? }
          close_iq_source(source: src) if defined?(src) && src
          spinner&.stop if defined?(spinner)
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE (100 % ruby-native — no external binaries):
            #{self}.run_native(
              freq_obj: 'required - freq_obj from PWN::SDR::GQRX.init_freq',
              protocol: 'required - short protocol name',
              demod:    'required - object with #feed(samples,&emit)',
              rate:     'optional - UDP sample rate (default 48000)'
            )

            #{self}.run_iq(
              freq_obj:    'required - freq_obj Hash',
              protocol:    'required - short protocol name',
              demod:       'required - #feed_iq(iq, rate:, &emit) or #feed',
              sample_rate: 'optional - Hz (default 2_048_000)',
              source:      'optional - :auto|:rtlsdr|:hackrf|:adalm_pluto|:soapy|:file',
              file:        'optional - .cu8/.cs16 capture path',
              fm_demod:    'optional - FM-demod then #feed (default false)',
              fallback:    'optional - :detector|:raise|:silent (default :detector)'
            )

            #{self}.run_detector(
              freq_obj:  'required - freq_obj from PWN::SDR::GQRX.init_freq',
              protocol:  'required - short protocol name',
              note:      'optional - explanation shown to operator',
              threshold: 'optional - dB above floor for burst (default 8.0)',
              describe:  'optional - Proc { |burst| Hash } extra fields'
            )

            #{self}.resolve_iq_source(freq_obj:, source: :auto, sample_rate:, file:)
            #{self}.match_line?(line: str, matcher: Regexp|String|Array)

            #{self}.authors
          "
        end
      end
    end
  end
end
