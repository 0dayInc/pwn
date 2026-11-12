# frozen_string_literal: true

require 'json'
require 'socket'

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
      #                 demodulator emits is merged with freq_obj and written
      #                 as flushed JSONL, then delivered to on_frame.
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
      #
      # All runners accept on_frame (callable), output (IO, default $stdout),
      # interactive (default true), duration (monotonic seconds), stop (callable),
      # queue_size (positive Integer, default 8), and log_file (nil: default
      # /tmp/<protocol>_decoder_<date>.log; false: disabled; String: append path).
      # EOF drains the bounded queue and returns without waiting for ENTER.
      # Native/IQ demods may implement #flush(&emit), called once at clean EOF
      # after sample validation, never as cancellation/error cleanup.
      # Audio :rate (IQ audio :sample_rate) declares the demod's configured
      # timing. Source descriptors with differing :rate_hz are rejected;
      # no implicit resampling or demodulator reconfiguration is performed.
      # Stop/deadline/ENTER cancel pending work; errors propagate after cleanup.
      # Return: reason, bytes_processed, chunks_processed, frames, queue_size,
      # queue_high_water (observed), backpressure_waits. These describe this
      # handoff, not RF/UDP packet loss or guaranteed hardware realtime speed.
      # Caller-supplied input IOs are closed; output IO is flushed, not closed.
      module Base
        # Supported Method Parameters::
        # PWN::SDR::Decoder::Base.run_native(
        #   freq_obj: 'required - freq_obj Hash from PWN::SDR::GQRX.init_freq',
        #   protocol: 'required - short name for banner / log filename',
        #   demod:    'required - object responding to #feed(samples,&emit)',
        #   rate:     'optional - assumed UDP sample rate (default 48000)'
        # )

        public_class_method def self.run_native(opts = {})
          demod = opts[:demod]
          raise 'ERROR: :freq_obj is required' unless opts[:freq_obj].is_a?(Hash)
          raise 'ERROR: :demod must respond to #feed' unless demod.respond_to?(:feed)

          run_audio(opts) do |samples, emit|
            if samples.nil?
              demod.flush(&emit) if demod.respond_to?(:flush)
            else
              demod.feed(samples, &emit)
            end
          end
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
          protocol = opts[:protocol] || 'SIGNAL'
          threshold = (opts[:threshold] || 8.0).to_f
          rate = (opts[:rate] || 48_000).to_f
          raise 'ERROR: :freq_obj is required' unless opts[:freq_obj].is_a?(Hash)
          raise ArgumentError, ':rate must be positive' unless rate.positive?

          floor = nil
          burst_start = nil
          peak = -200.0
          count = 0
          elapsed = 0.0
          run_audio(opts.merge(allow_level: true)) do |samples, emit|
            level = samples.is_a?(Numeric) ? samples : samples && PWN::SDR::Decoder::DSP.rms_dbfs(samples: samples)
            floor = floor.nil? ? level : (floor * 0.98) + (level * 0.02) if level
            if level && level - floor >= threshold
              burst_start ||= elapsed
              peak = [peak, level].max
            elsif burst_start
              count += 1
              duration_ms = ((elapsed - burst_start) * 1000).round
              msg = { protocol: protocol, event: 'burst', burst_no: count,
                      peak_dbfs: peak.round(1), floor_dbfs: floor.round(1),
                      delta_db: (peak - floor).round(1), duration_ms: duration_ms,
                      summary: "#{protocol} burst ##{count} peak=#{peak.round(1)} dBFS duration=#{duration_ms} ms" }
              msg.merge!(opts[:describe].call(msg)) if opts[:describe].respond_to?(:call)
              emit.call(msg)
              burst_start = nil
              peak = -200.0
            end
            elapsed += samples.is_a?(Numeric) ? 0.1 : samples.length / rate if samples
          end
        end

        # Sources are owned for the duration of a run and closed on every exit.
        # Audio fixtures are raw s16le mono; IQ fixtures use resolve_iq_source.
        private_class_method def self.run_audio(opts = {})
          freq_obj = opts[:freq_obj]
          source = opts[:source]
          bytes = Integer(opts[:chunk_bytes] || 4096)
          raise ArgumentError, ':chunk_bytes must be positive' unless bytes.positive?

          io = if opts[:file]
                 File.open(opts[:file], 'rb')
               elsif source.is_a?(Hash)
                 source[:io] || File.open(source.fetch(:path), 'rb')
               elsif source.respond_to?(:read) || source.respond_to?(:recv)
                 source
               else
                 begin
                   PWN::SDR::GQRX.listen_udp(udp_ip: freq_obj[:udp_ip] || '127.0.0.1', udp_port: freq_obj[:udp_port] || 7355)
                 rescue SystemCallError
                   raise unless opts[:allow_level] && freq_obj[:gqrx_sock]

                   nil
                 end
               end
          # #feed has no rate argument: callers must configure their demodulator
          # with :rate, rather than silently changing timing from the descriptor.
          rate = Float(opts[:rate] || 48_000)
          actual_rate = source.is_a?(Hash) && !opts[:file] ? Float(source.fetch(:rate_hz, rate)) : rate
          raise ArgumentError, ':rate must be finite and positive' unless rate.finite? && rate.positive?
          raise ArgumentError, "Audio source rate #{actual_rate} differs from configured rate #{rate}" unless actual_rate == rate

          reader = lambda do
            if io.nil?
              sleep 0.1
              Float(PWN::SDR::GQRX.cmd(gqrx_sock: freq_obj[:gqrx_sock], cmd: 'l STRENGTH'))
            elsif io.is_a?(UDPSocket)
              # Read the complete datagram, never truncate it to chunk_bytes.
              io.recv(65_535)
            elsif io.respond_to?(:readpartial)
              io.readpartial(bytes)
            else
              data = io.read(bytes)
              data.to_s.empty? ? nil : data
            end
          rescue EOFError
            nil
          end
          carry = ''.b
          run_stream(opts.merge(log_obj: strip_freq_obj(freq_obj: freq_obj), reader: reader)) do |raw, emit|
            if raw.is_a?(Numeric)
              yield raw, emit
              next
            end
            if raw.nil?
              raise IOError, 'Incomplete audio sample at EOF' unless carry.empty?

              yield nil, emit
              next
            end
            carry << raw
            length = carry.bytesize / 2 * 2
            next if length.zero?

            yield PWN::SDR::Decoder::DSP.unpack_s16le(data: carry.slice!(0, length)), emit
          end
        ensure
          io&.close unless io&.closed?
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
        # path = PWN::SDR::Decoder::Base.log_path(protocol: 'POCSAG')

        private_class_method def self.log_path(opts = {})
          protocol = opts[:protocol].to_s
          "/tmp/#{protocol.downcase.gsub(/[^a-z0-9]+/, '_')}_decoder_#{Time.now.strftime('%Y%m%d')}.log"
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
          supplied = opts[:source]
          return supplied if supplied.is_a?(Hash)
          if supplied.respond_to?(:readpartial) || supplied.respond_to?(:read)
            return { kind: :io, io: supplied, format: opts[:iq_format] || :cu8,
                     rate_hz: opts[:sample_rate] || 2_048_000 }
          end
          want     = (supplied || freq_obj[:iq_source] || :auto).to_s.downcase.to_sym
          rate     = (opts[:sample_rate] || freq_obj[:iq_rate] || 2_048_000).to_i
          file     = opts[:file] || freq_obj[:iq_file]
          if want == :file || file
            raise ArgumentError, ':file is required for a file source' if file.to_s.empty?
            raise Errno::ENOENT, file.to_s unless File.file?(file.to_s)

            want = :file if want == :auto
          end
          freq_hz = begin
            PWN::SDR.hz_to_i(freq: freq_obj[:freq])
          rescue StandardError
            freq_obj[:freq].to_i
          end

          try = lambda do |kind|
            owned = nil
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
              owned = { kind: kind, device: dev }
              PWN::FFI::RTLSdr.configure(
                device: dev, freq_hz: freq_hz, rate_hz: rate,
                gain_db: opts[:gain_db] || freq_obj[:gain_db],
                ppm: opts[:ppm] || freq_obj[:ppm] || 0
              )
              { kind: :rtlsdr, device: dev, rate_hz: rate, freq_hz: freq_hz, format: :cu8 }
            when :hackrf
              return nil unless PWN::FFI.available?(mod: :HackRF)

              dev = PWN::FFI::HackRF.open(serial: opts[:serial])
              owned = { kind: kind, device: dev }
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
              owned = { kind: :adalm_pluto, context: ctx }
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
              owned = { kind: kind, handle: h }
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
            close_iq_source(source: owned) if owned
            raise unless want == :auto

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

          raise IOError, 'I/Q continuity lost: source reports dropped samples' if iq_stream_status(source: src)[:discontinuity]

          data = case src[:kind]
                 when :file, :io
                   src[:io] ||= File.open(src[:path], 'rb')
                   data = src[:io].respond_to?(:readpartial) ? src[:io].readpartial(bytes) : src[:io].read(bytes)
                   data.to_s.empty? ? nil : data
                 when :rtlsdr
                   (src[:read_mutex] ||= Mutex.new).synchronize do
                     PWN::FFI::RTLSdr.read_sync(device: src[:device], bytes: bytes)
                   end
                 when :adalm_pluto
                   PWN::FFI::AdalmPluto.read_sync(handle: src[:handle])
                 when :hackrf
                   PWN::FFI::HackRF.read_sync(handle: src[:handle])
                 when :soapy
                   (src[:read_mutex] ||= Mutex.new).synchronize do
                     PWN::FFI::SoapySDR.read_sync(handle: src[:handle], timeout_us: 100_000)
                   end
                 else
                   raise ArgumentError, "Unknown I/Q source: #{src[:kind]}"
                 end
          raise IOError, 'I/Q continuity lost: source reports dropped samples' if iq_stream_status(source: src)[:discontinuity]

          if data.nil? && %i[rtlsdr hackrf adalm_pluto soapy].include?(src[:kind]) && !src.dig(:handle, :stopped)
            sleep 0.005
            return ''.b # A hardware timeout is not capture EOF.
          end
          data
        rescue EOFError
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
          when :cu8
            PWN::SDR::Decoder::DSP.unpack_cu8(data: data)
          else
            raise ArgumentError, "Unsupported IQ format: #{src[:format]}"
          end
        end

        # Supported Method Parameters::
        # PWN::SDR::Decoder::Base.close_iq_source(source: handle)

        public_class_method def self.close_iq_source(opts = {})
          src = opts[:source]
          return unless src.is_a?(Hash)

          case src[:kind]
          when :file, :io
            src[:io]&.close unless src[:io]&.closed?
          when :rtlsdr
            (src[:read_mutex] ||= Mutex.new).synchronize do
              PWN::FFI::RTLSdr.close(device: src[:device]) if src[:device]
            end
          when :adalm_pluto
            PWN::FFI::AdalmPluto.stop_rx(handle: src[:handle]) if src[:handle]
            PWN::FFI::AdalmPluto.close(context: src[:context]) if src[:context]
          when :hackrf
            PWN::FFI::HackRF.stop_rx(handle: src[:handle]) if src[:handle]
            PWN::FFI::HackRF.close(device: src[:device]) if src[:device]
          when :soapy
            (src[:read_mutex] ||= Mutex.new).synchronize do
              PWN::FFI::SoapySDR.close(handle: src[:handle]) if src[:handle]
            end
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
        #   chunk_bytes: 'optional - bytes per read (default 16384)',
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
          chunk_b  = (opts[:chunk_bytes] || 16_384).to_i
          fallback = (opts[:fallback] || :detector).to_sym

          raise 'ERROR: :freq_obj is required' unless freq_obj.is_a?(Hash)
          raise 'ERROR: :demod required' if demod.nil?
          raise ArgumentError, ':sample_rate must be positive' unless rate.positive?

          src = resolve_iq_source(opts.merge(sample_rate: rate, chunk_samples: opts[:chunk_samples] || (chunk_b / 4)))

          unless src && src[:streaming] != false
            case fallback
            when :raise
              raise 'ERROR: no I/Q source available (RTL-SDR / ADALM-Pluto / HackRF / SoapySDR / file)'
            when :silent
              return nil
            else
              return run_detector(opts.merge(source: nil, file: nil,
                                             note: opts[:note] || "No I/Q source — energy detector only for #{protocol}."))
            end
          end

          # Audio demods have fixed timing and cannot consume feed_iq's rate
          # keyword. No implicit resampling or private demod state mutation.
          actual_rate = src[:rate_hz] || rate
          raise ArgumentError, 'I/Q source rate must be finite and positive' unless Float(actual_rate).finite? && Float(actual_rate).positive?
          raise ArgumentError, "Unsupported IQ format: #{src[:format]}" unless %w[cu8 cs8 cs16].include?((src[:format] || :cu8).to_s)
          # Rates are configuration values, not computed DSP measurements.
          raise ArgumentError, "Audio source rate #{actual_rate} differs from configured sample_rate #{rate}" if (fm_demod || !demod.respond_to?(:feed_iq)) && Float(actual_rate) != rate # rubocop:disable Lint/FloatComparison

          rate = actual_rate
          log_obj = strip_freq_obj(freq_obj: freq_obj).merge(
            iq_source: src[:kind], iq_rate: rate, iq_format: src[:format]
          )

          raise ArgumentError, ':chunk_bytes must be positive' unless chunk_b.positive?
          raise ArgumentError, 'demod must respond to #feed_iq or #feed' unless demod.respond_to?(:feed_iq) || demod.respond_to?(:feed)

          carry = ''.b
          previous = nil
          width = src[:format].to_s == 'cs16' ? 4 : 2
          cancel_read = -> { PWN::FFI::AdalmPluto.stop_rx(handle: src[:handle]) } if src[:kind] == :adalm_pluto
          result = run_stream(opts.merge(log_obj: log_obj, cancel_read: cancel_read,
                                         reader: -> { read_iq_chunk(source: src, bytes: chunk_b) })) do |raw, emit|
            raise IOError, 'I/Q continuity lost: source reports dropped samples' if iq_stream_status(source: src)[:discontinuity]

            if raw.nil?
              raise IOError, "Incomplete I/Q sample at EOF (#{carry.bytesize} bytes)" unless carry.empty?

              demod.flush(&emit) if demod.respond_to?(:flush)
              next
            end
            carry << raw
            length = carry.bytesize / width * width
            next if length.zero?

            iq = unpack_iq(source: src, data: carry.slice!(0, length))
            if fm_demod && demod.respond_to?(:feed)
              continuous = previous ? previous + iq : iq
              previous = iq.last(2)
              demod.feed(PWN::SDR::Decoder::DSP.fm_demod_iq(iq: continuous), &emit)
            elsif demod.respond_to?(:feed_iq)
              demod.feed_iq(iq, rate: rate, &emit)
            else
              demod.feed(PWN::SDR::Decoder::DSP.mag_sq(iq: iq).map { |v| Math.sqrt(v) }, &emit)
            end
          end
          status = iq_stream_status(source: src)
          raise IOError, 'I/Q continuity lost: source reports dropped samples' if status[:discontinuity]

          result.merge(status).merge(capture_complete: result[:reason] == :eof)
        rescue StandardError => e
          status = iq_stream_status(source: src).merge(reason: :error, capture_complete: false,
                                                       error_class: e.class.name, error_message: e.message).freeze
          e.define_singleton_method(:stream_stats) { status }
          raise
        ensure
          close_iq_source(source: src) if defined?(src) && src
        end

        # Unknown device telemetry stays nil, never a fabricated zero loss count.
        private_class_method def self.iq_stream_status(opts = {})
          source = opts[:source]
          handle = source.is_a?(Hash) && source[:handle].is_a?(Hash) ? source[:handle] : {}
          overruns = handle[:overruns]
          dropped = handle[:dropped_bytes]
          loss = (overruns && overruns.positive?) || (dropped && dropped.positive?)
          { overruns: overruns, dropped_bytes: dropped,
            discontinuity: if loss
                             true
                           else
                             (overruns.nil? && dropped.nil? ? nil : false)
                           end }
        end

        # A bounded lossless handoff; one consumer serializes demodulation,
        # rendering, logging and callbacks. The supervisor remains responsive
        # even while a read, queue push, demodulator or callback is blocked.
        private_class_method def self.run_stream(opts = {})
          reader = opts[:reader]
          output = opts.fetch(:output, $stdout)
          callback = opts[:on_frame]
          stop = opts[:stop]
          size = Integer(opts.fetch(:queue_size, 8))
          raise ArgumentError, ':queue_size must be positive' unless size.positive?
          raise ArgumentError, ':on_frame must be callable' if callback && !callback.respond_to?(:call)
          raise ArgumentError, ':stop must be callable' if stop && !stop.respond_to?(:call)

          duration = opts[:duration] && Float(opts[:duration])
          raise ArgumentError, ':duration must be finite and nonnegative' if duration && (!duration.finite? || duration.negative?)

          deadline = duration && (Process.clock_gettime(Process::CLOCK_MONOTONIC) + duration)
          log_file = opts[:log_file]
          log_file = log_path(protocol: opts[:protocol] || 'SIGNAL') if log_file.nil?
          # Run-owned handle: closed in ensure after both workers terminate.
          log = File.open(log_file, 'a') unless log_file == false # rubocop:disable Style/FileOpen
          queue = SizedQueue.new(size)
          stats = { reason: :eof, bytes_processed: 0, chunks_processed: 0, frames: 0,
                    queue_high_water: 0, backpressure_waits: 0, queue_size: size }
          emit = proc do |msg|
            next unless msg.is_a?(Hash)

            final = opts[:log_obj].merge(decoded_at: Time.now.strftime('%Y-%m-%d %H:%M:%S%z')).merge(msg)
            line = JSON.generate(final)
            output.puts(line)
            output.flush if output.respond_to?(:flush)
            log&.puts(line)
            log&.flush
            callback&.call(final)
            stats[:frames] += 1
          end
          producer = Thread.new do
            Thread.current.report_on_exception = false
            loop do
              raw = reader.call
              break if raw.nil?
              next if raw.is_a?(String) && raw.empty?

              begin
                queue.push(raw, true)
              rescue ThreadError
                stats[:backpressure_waits] += 1
                queue.push(raw)
              end
              stats[:queue_high_water] = [stats[:queue_high_water], queue.length].max
            end
          ensure
            queue.close
          end
          consumer = Thread.new do
            Thread.current.report_on_exception = false
            while (raw = queue.pop)
              yield raw, emit
              stats[:bytes_processed] += raw.bytesize if raw.respond_to?(:bytesize)
              stats[:chunks_processed] += 1
            end
            # Queue closure also happens on reader errors and cancellation.
            # Join the producer before treating a drained queue as clean EOF.
            producer.value
            yield nil, emit if stats[:reason] == :eof
          end
          loop do
            producer.value unless producer.alive?
            unless consumer.alive?
              consumer.value
              break
            end
            if stop&.call
              stats[:reason] = :stop
              break
            end
            if deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
              stats[:reason] = :duration
              break
            end
            if opts.fetch(:interactive, true) && $stdin.respond_to?(:read_nonblock)
              begin
                if $stdin.read_nonblock(1, exception: false) == "\n"
                  stats[:reason] = :enter
                  break
                end
              rescue IOError
                # A closed/non-interactive stdin is not a stream EOF.
                nil
              end
            end
            sleep 0.005
          end
          completed = true
          stats
        ensure
          # Cleanup may unblock the producer with EOF; that is not clean input
          # completion when the supervisor itself failed or was interrupted.
          # A caller's handled exception ($!) is not a failure of this run.
          stats[:reason] = :error if stats && !completed
          queue&.close
          begin
            opts[:cancel_read]&.call
          ensure
            [producer, consumer].compact.each do |thread|
              thread.kill if thread.alive?
              thread.join(1)
            rescue StandardError
              nil
            end
            log&.close
          end
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            # Common options for run_native, run_detector and run_iq:
            # on_frame: callable receiving each metadata-enriched Hash after output/log flush
            # output: IO (default $stdout), written as JSONL; not closed by the runner
            # interactive: true by default; ENTER cancels, stdin EOF does not cancel
            # duration: optional finite nonnegative seconds measured with a monotonic clock
            # stop: optional quick, nonblocking callable; truthy cancels pending work
            # queue_size: positive Integer (default 8); full queue blocks the producer
            # log_file: nil uses /tmp/<protocol>_decoder_<date>.log, false disables, path appends JSONL
            # source: input IO or source handle; file: raw fixture path; inputs are closed on exit
            # Audio fixtures: s16le mono; IQ: cu8 (default), cs8 or cs16 via iq_format
            # EOF drains and exits automatically; worker errors propagate after cleanup
            # Returns a Hash: reason (:eof/:stop/:duration/:enter), bytes_processed,
            # chunks_processed, frames, queue_size, queue_high_water, backpressure_waits
            # IQ also returns overruns/dropped_bytes (nil if unknown), discontinuity,
            # capture_complete (true only on clean EOF). Loss aborts; never bridge a gap.
            # IQ exceptions expose stream_stats with telemetry and original error details.
            # Queue metrics do not measure RF/UDP packet loss or guarantee hardware throughput.

            # Run run native and return its result
            #{self}.run_native(
              freq_obj: 'required - freq_obj Hash from PWN::SDR::GQRX.init_freq',
              protocol: 'required - short name for banner / log filename (defaults to SIGNAL)',
              demod: 'required - object responding to #feed(samples,&emit)',
              rate: 'optional - assumed UDP sample rate (default 48000)'
            )

            # Run run detector and return its result
            #{self}.run_detector(
              freq_obj: 'required - freq_obj Hash from PWN::SDR::GQRX.init_freq',
              protocol: 'required - short name for banner / log filename (defaults to SIGNAL)',
              note: 'optional - one-line explanation shown once',
              threshold: 'optional - dBFS above rolling floor to call a burst (default 8.0)',
              describe: 'optional - Proc.new { |burst_hash| Hash } extra fields'
            )

            # Run match line and return its result
            #{self}.match_line?(
              line: 'optional - line value consumed by #match_line?',
              matcher: 'optional - matcher value consumed by #match_line?'
            )

            # Run resolve iq source and return its result
            #{self}.resolve_iq_source(
              freq_obj: 'required - freq obj value consumed by #resolve_iq_source',
              source: 'optional - :auto|:rtlsdr|:hackrf|:adalm_pluto|:soapy|:file',
              sample_rate: 'optional - desired rate Hz',
              file: 'optional - path to .cu8/.cs16/.iq capture (defaults to freq_obj[:iq_file])',
              iq_format: 'optional - iq format value consumed by #resolve_iq_source (defaults to freq_obj[:iq_format])',
              index: 'optional - index value consumed by #resolve_iq_source',
              gain_db: 'optional - gain db value consumed by #resolve_iq_source (defaults to freq_obj[:gain_db])',
              ppm: 'optional - ppm value consumed by #resolve_iq_source',
              serial: 'optional - serial value consumed by #resolve_iq_source',
              lna_gain: 'optional - lna gain value consumed by #resolve_iq_source (defaults to 16)',
              vga_gain: 'optional - vga gain value consumed by #resolve_iq_source (defaults to 20)',
              amp: 'optional - amp value consumed by #resolve_iq_source',
              uri: 'optional - URI or URL string',
              chunk_samples: 'optional - chunk samples value consumed by #resolve_iq_source',
              soapy_args: 'optional - soapy args value consumed by #resolve_iq_source (defaults to freq_obj[:soapy_args])',
              channel: 'optional - channel value consumed by #resolve_iq_source (defaults to 0)'
            )

            # Run read iq chunk and return its result
            #{self}.read_iq_chunk(
              source: 'required - source value consumed by #read_iq_chunk',
              bytes: 'optional - bytes value consumed by #read_iq_chunk'
            )

            # Run unpack iq and return its result
            #{self}.unpack_iq(
              source: 'optional - source value consumed by #unpack_iq',
              data: 'optional - data value consumed by #unpack_iq'
            )

            # Run close iq source and return its result
            #{self}.close_iq_source(
              source: 'optional - source value consumed by #close_iq_source'
            )

            # OR #feed(samples, &emit) when fm_demod:true,
            #{self}.run_iq(
              freq_obj: 'required - freq_obj Hash',
              protocol: 'required - short name (defaults to SIGNAL)',
              demod: 'required - object with #feed_iq(iq, rate:, &emit',
              sample_rate: 'optional - Hz (default 2_048_000)',
              source: 'optional - :auto|:rtlsdr|:hackrf|:adalm_pluto|:soapy|:file',
              file: 'optional - path to capture',
              fm_demod: 'optional - FM-demod I/Q→audio then #feed (default false)',
              chunk_bytes: 'optional - bytes per read (default 16384; audio runners default 4096)',
              fallback: 'optional - :detector|:raise|:silent (default :detector)',
              note: 'optional - shown once when falling back',
              describe: 'optional - Proc for detector fallback',
              gain_db: 'optional - gain db value consumed by #run_iq',
              uri: 'optional - URI or URL string',
              index: 'optional - index value consumed by #run_iq',
              threshold: 'optional - threshold value consumed by #run_iq'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end
      end
    end
  end
end
