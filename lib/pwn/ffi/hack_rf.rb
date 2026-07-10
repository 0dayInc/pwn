# frozen_string_literal: true

require 'ffi'

PubFFI = ::FFI unless defined?(PubFFI) # rubocop:disable Style/RedundantConstantBase

module PWN
  module FFI
    # Thin libhackrf binding for inventory / RX of raw I/Q.
    #
    # Intentionally control-plane first: init/open/tune/rate/gains + one-shot
    # sync-style helpers used by Extrospection `probe_rf` and by wideband
    # PWN::SDR::Decoder::* modules that need real I/Q (not GQRX audio).
    # Streaming callbacks stay opt-in — Ruby GC must not run on the
    # libusb transfer thread, so call sites that need continuous RX should
    # buffer into a Queue from a dedicated thread.
    module HackRF
      extend PubFFI::Library

      HACKRF_SUCCESS = 0

      @load_error = nil
      begin
        ffi_lib %w[hackrf libhackrf.so.0 libhackrf.so]
      rescue LoadError => e
        @load_error = e
      end

      class << self
        attr_reader :load_error
      end

      unless @load_error
        attach_function :hackrf_init, [], :int
        attach_function :hackrf_exit, [], :int
        attach_function :hackrf_library_version, [], :string
        attach_function :hackrf_library_release, [], :string
        attach_function :hackrf_error_name, [:int], :string

        attach_function :hackrf_open, [:pointer], :int
        attach_function :hackrf_open_by_serial, %i[string pointer], :int
        attach_function :hackrf_close, [:pointer], :int

        attach_function :hackrf_set_freq, %i[pointer uint64], :int
        attach_function :hackrf_set_sample_rate, %i[pointer double], :int
        attach_function :hackrf_set_baseband_filter_bandwidth, %i[pointer uint32], :int
        attach_function :hackrf_set_vga_gain, %i[pointer uint32], :int
        attach_function :hackrf_set_lna_gain, %i[pointer uint32], :int
        attach_function :hackrf_set_amp_enable, %i[pointer uint8], :int
        attach_function :hackrf_is_streaming, [:pointer], :int
        # int (*hackrf_sample_block_cb_fn)(hackrf_transfer* transfer)
        callback :hackrf_sample_block_cb_fn, [:pointer], :int
        attach_function :hackrf_start_rx, %i[pointer hackrf_sample_block_cb_fn pointer], :int
        attach_function :hackrf_stop_rx, [:pointer], :int
        attach_function :hackrf_board_id_read, %i[pointer pointer], :int
        attach_function :hackrf_board_id_name, [:uint8], :string
        attach_function :hackrf_version_string_read, %i[pointer pointer uint8], :int
      end

      # Supported Method Parameters::
      # PWN::FFI::HackRF.available?

      public_class_method def self.available?
        !@load_error && respond_to?(:hackrf_init, true)
      rescue StandardError
        false
      end

      # Supported Method Parameters::
      # info = PWN::FFI::HackRF.info
      # Returns Hash with library_version / library_release / available.

      public_class_method def self.info
        return { available: false, error: @load_error&.message } unless available?

        {
          available: true,
          library_version: hackrf_library_version.to_s,
          library_release: hackrf_library_release.to_s
        }
      end

      # Supported Method Parameters::
      # dev = PWN::FFI::HackRF.open(serial: nil)
      # Returns FFI::Pointer (opaque hackrf_device*) or raises.

      public_class_method def self.open(opts = {})
        raise 'ERROR: libhackrf not available' unless available?

        check!(hackrf_init)
        dev_ptr = PubFFI::MemoryPointer.new(:pointer)
        serial = opts[:serial]
        rc = if serial
               hackrf_open_by_serial(serial.to_s, dev_ptr)
             else
               hackrf_open(dev_ptr)
             end
        check!(rc)
        dev_ptr.read_pointer
      end

      # Supported Method Parameters::
      # PWN::FFI::HackRF.close(device: pointer)

      public_class_method def self.close(opts = {})
        dev = opts[:device]
        return unless dev && !dev.null?

        check!(hackrf_close(dev))
        hackrf_exit
        nil
      end

      # Supported Method Parameters::
      # PWN::FFI::HackRF.configure(
      #   device:     'required - pointer from .open',
      #   freq_hz:    'required - center frequency Hz',
      #   rate_hz:    'optional - sample rate (default 10e6)',
      #   lna_gain:   'optional - 0..40 step 8 (default 16)',
      #   vga_gain:   'optional - 0..62 step 2 (default 20)',
      #   amp:        'optional - true/false RF amp (default false)',
      #   bb_bw_hz:   'optional - baseband filter BW Hz'
      # )

      public_class_method def self.configure(opts = {}) # rubocop:disable Naming/PredicateMethod
        dev = opts[:device]
        raise 'ERROR: :device required' if dev.nil? || dev.null?

        freq = opts[:freq_hz].to_i
        rate = (opts[:rate_hz] || 10_000_000).to_f
        lna  = (opts[:lna_gain] || 16).to_i
        vga  = (opts[:vga_gain] || 20).to_i
        amp  = opts[:amp] ? 1 : 0

        check!(hackrf_set_freq(dev, freq))
        check!(hackrf_set_sample_rate(dev, rate))
        check!(hackrf_set_lna_gain(dev, lna))
        check!(hackrf_set_vga_gain(dev, vga))
        check!(hackrf_set_amp_enable(dev, amp))
        check!(hackrf_set_baseband_filter_bandwidth(dev, opts[:bb_bw_hz].to_i)) if opts[:bb_bw_hz]
        true
      end

      # Supported Method Parameters::
      # meta = PWN::FFI::HackRF.device_info(device: pointer)
      # Returns { board_id:, board_name:, version: }

      public_class_method def self.device_info(opts = {})
        dev = opts[:device]
        raise 'ERROR: :device required' if dev.nil? || dev.null?

        bid_ptr = PubFFI::MemoryPointer.new(:uint8)
        check!(hackrf_board_id_read(dev, bid_ptr))
        bid = bid_ptr.read_uint8
        ver_buf = PubFFI::MemoryPointer.new(:char, 255)
        check!(hackrf_version_string_read(dev, ver_buf, 255))
        {
          board_id: bid,
          board_name: hackrf_board_id_name(bid).to_s,
          version: ver_buf.read_string
        }
      end
      # hackrf_transfer as passed to the RX callback.
      class Transfer < PubFFI::Struct
        layout :device,        :pointer,
               :buffer,        :pointer,
               :buffer_length, :int,
               :valid_length,  :int,
               :rx_ctx,        :pointer,
               :tx_ctx,        :pointer
      end

      # Supported Method Parameters::
      # rx = PWN::FFI::HackRF.start_rx(
      #   device:    'required - pointer from .open',
      #   max_queue: 'optional - max buffered chunks (default 64)'
      # )
      # Returns { device:, queue:, callback: } handle for read_sync/stop_rx.
      # libhackrf runs the callback on its own libusb thread; FFI acquires
      # the GVL for us, so keep the callback body to a bare byte copy.

      public_class_method def self.start_rx(opts = {})
        raise 'ERROR: libhackrf not available' unless available?

        dev = opts[:device]
        raise 'ERROR: :device required' if dev.nil? || dev.null?

        max_q = (opts[:max_queue] || 64).to_i
        queue = Queue.new
        cb = PubFFI::Function.new(:int, [:pointer]) do |xfer_ptr|
          begin
            xfer = Transfer.new(xfer_ptr)
            len  = xfer[:valid_length].to_i
            queue.push(xfer[:buffer].read_bytes(len)) if len.positive? && queue.size < max_q
          rescue StandardError
            nil
          end
          0
        end
        check!(hackrf_start_rx(dev, cb, nil))
        { device: dev, queue: queue, callback: cb }
      end

      # Supported Method Parameters::
      # data = PWN::FFI::HackRF.read_sync(
      #   handle:  'required - handle from .start_rx',
      #   timeout: 'optional - seconds to wait for a chunk (default 1.0)'
      # )
      # Returns String of interleaved cs8 I/Q, or nil on timeout.

      public_class_method def self.read_sync(opts = {})
        h = opts[:handle]
        raise 'ERROR: :handle required (from start_rx)' unless h.is_a?(Hash) && h[:queue]

        q  = h[:queue]
        to = (opts[:timeout] || 1.0).to_f
        deadline = Time.now + to
        while q.empty?
          return nil if Time.now > deadline

          sleep 0.005
        end
        q.pop
      end

      # Supported Method Parameters::
      # PWN::FFI::HackRF.stop_rx(handle: rx)

      public_class_method def self.stop_rx(opts = {})
        h = opts[:handle]
        return unless h.is_a?(Hash) && h[:device]

        hackrf_stop_rx(h[:device])
        h[:queue]&.clear
        h[:callback] = nil
        nil
      rescue StandardError
        nil
      end

      # Supported Method Parameters::
      # data = PWN::FFI::HackRF.capture(
      #   freq_hz:  'required - center frequency Hz',
      #   rate_hz:  'optional - sample rate (default 10e6)',
      #   samples:  'optional - I/Q sample pairs to capture (default 262_144)',
      #   lna_gain: 'optional', vga_gain: 'optional', amp: 'optional',
      #   serial:   'optional'
      # )
      # One-shot open/configure/start_rx/read/stop_rx/close.
      # Returns String of interleaved cs8 I/Q.

      public_class_method def self.capture(opts = {})
        want = (opts[:samples] || 262_144).to_i * 2
        dev  = self.open(serial: opts[:serial])
        configure(
          device: dev,
          freq_hz: opts[:freq_hz],
          rate_hz: opts[:rate_hz] || 10_000_000,
          lna_gain: opts[:lna_gain], vga_gain: opts[:vga_gain], amp: opts[:amp]
        )
        rx  = start_rx(device: dev)
        buf = +''
        while buf.bytesize < want
          chunk = read_sync(handle: rx, timeout: 2.0)
          break unless chunk

          buf << chunk
        end
        buf[0, want]
      ensure
        stop_rx(handle: rx) if defined?(rx) && rx
        close(device: dev)  if defined?(dev) && dev
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.available?
          #{self}.info
          dev = #{self}.open(serial: nil)
          #{self}.configure(device: dev, freq_hz:, rate_hz: 10e6, lna_gain: 16, vga_gain: 20, amp: false)
          rx = #{self}.start_rx(device: dev)
          data = #{self}.read_sync(handle: rx)   # cs8 interleaved I/Q
          #{self}.stop_rx(handle: rx)
          data = #{self}.capture(freq_hz:, rate_hz: 10e6, samples: 262_144)
          #{self}.device_info(device: dev)
          #{self}.close(device: dev)

          #{self}.authors
        "
      end

      class << self
        private

        def check!(code)
          return if code == HACKRF_SUCCESS

          name = available? ? hackrf_error_name(code).to_s : code.to_s
          raise "ERROR: libhackrf rc=#{code} (#{name})"
        end
      end
    end
  end
end
