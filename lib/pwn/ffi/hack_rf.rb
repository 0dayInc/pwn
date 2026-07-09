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
