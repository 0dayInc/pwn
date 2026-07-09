# frozen_string_literal: true

require 'ffi'

PubFFI = ::FFI unless defined?(PubFFI) # rubocop:disable Style/RedundantConstantBase

module PWN
  module FFI
    # Thin librtlsdr binding (no -dev headers required — symbols resolved
    # from the installed shared object). Control-plane + blocking
    # `read_sync` so PWN::SDR::Decoder::* / Extrospection probe_rf can pull
    # raw u8 I/Q without shelling out to `rtl_sdr`.
    #
    # If librtlsdr is missing `.available?` is false and callers fall back.
    module RTLSdr
      extend PubFFI::Library

      @load_error = nil
      begin
        ffi_lib %w[rtlsdr librtlsdr.so.0 librtlsdr.so.2 librtlsdr.so]
      rescue LoadError => e
        @load_error = e
      end

      class << self
        attr_reader :load_error
      end

      unless @load_error
        attach_function :rtlsdr_get_device_count, [], :uint32
        attach_function :rtlsdr_get_device_name, [:uint32], :string
        attach_function :rtlsdr_get_device_usb_strings,
                        %i[uint32 pointer pointer pointer],
                        :int
        attach_function :rtlsdr_open, %i[pointer uint32], :int
        attach_function :rtlsdr_close, [:pointer], :int
        attach_function :rtlsdr_set_center_freq, %i[pointer uint32], :int
        attach_function :rtlsdr_get_center_freq, [:pointer], :uint32
        attach_function :rtlsdr_set_sample_rate, %i[pointer uint32], :int
        attach_function :rtlsdr_get_sample_rate, [:pointer], :uint32
        attach_function :rtlsdr_set_tuner_gain_mode, %i[pointer int], :int
        attach_function :rtlsdr_set_tuner_gain, %i[pointer int], :int
        attach_function :rtlsdr_get_tuner_gains, %i[pointer pointer], :int
        attach_function :rtlsdr_set_freq_correction, %i[pointer int], :int
        attach_function :rtlsdr_reset_buffer, [:pointer], :int
        attach_function :rtlsdr_read_sync,
                        %i[pointer pointer int pointer],
                        :int
        attach_function :rtlsdr_set_agc_mode, %i[pointer int], :int
      end

      # Supported Method Parameters::
      # PWN::FFI::RTLSdr.available?

      public_class_method def self.available?
        !@load_error && respond_to?(:rtlsdr_get_device_count, true)
      rescue StandardError
        false
      end

      # Supported Method Parameters::
      # devices = PWN::FFI::RTLSdr.list_devices
      # Returns Array<Hash> of { index:, name:, manufacturer:, product:, serial: }.

      public_class_method def self.list_devices
        raise 'ERROR: librtlsdr not available' unless available?

        count = rtlsdr_get_device_count
        Array.new(count) do |i|
          mfr  = PubFFI::MemoryPointer.new(:char, 256)
          prod = PubFFI::MemoryPointer.new(:char, 256)
          ser  = PubFFI::MemoryPointer.new(:char, 256)
          rtlsdr_get_device_usb_strings(i, mfr, prod, ser)
          {
            index: i,
            name: (rtlsdr_get_device_name(i) || '').to_s,
            manufacturer: mfr.read_string,
            product: prod.read_string,
            serial: ser.read_string
          }
        end
      end

      # Supported Method Parameters::
      # dev = PWN::FFI::RTLSdr.open(index: 0)
      # Returns opaque FFI::Pointer (rtlsdr_dev_t*).

      public_class_method def self.open(opts = {})
        raise 'ERROR: librtlsdr not available' unless available?

        idx = (opts[:index] || 0).to_i
        dev_ptr = PubFFI::MemoryPointer.new(:pointer)
        rc = rtlsdr_open(dev_ptr, idx)
        raise "ERROR: rtlsdr_open rc=#{rc}" unless rc.zero?

        dev_ptr.read_pointer
      end

      # Supported Method Parameters::
      # PWN::FFI::RTLSdr.close(device: pointer)

      public_class_method def self.close(opts = {})
        dev = opts[:device]
        return unless dev && !dev.null?

        rtlsdr_close(dev)
        nil
      end

      # Supported Method Parameters::
      # PWN::FFI::RTLSdr.configure(
      #   device:   'required - pointer from .open',
      #   freq_hz:  'required - center frequency Hz',
      #   rate_hz:  'optional - sample rate (default 2.048e6)',
      #   gain_db:  'optional - tenths of dB (e.g. 496 = 49.6 dB). nil = auto',
      #   ppm:      'optional - freq correction ppm (default 0)'
      # )

      public_class_method def self.configure(opts = {}) # rubocop:disable Naming/PredicateMethod
        dev = opts[:device]
        raise 'ERROR: :device required' if dev.nil? || dev.null?

        freq = opts[:freq_hz].to_i
        rate = (opts[:rate_hz] || 2_048_000).to_i
        ppm  = (opts[:ppm] || 0).to_i

        check!(rtlsdr_set_sample_rate(dev, rate), 'set_sample_rate')
        check!(rtlsdr_set_center_freq(dev, freq), 'set_center_freq')
        check!(rtlsdr_set_freq_correction(dev, ppm), 'set_freq_correction') if ppm != 0

        if opts.key?(:gain_db) && !opts[:gain_db].nil?
          check!(rtlsdr_set_tuner_gain_mode(dev, 1), 'gain_mode manual')
          check!(rtlsdr_set_tuner_gain(dev, opts[:gain_db].to_i), 'set_tuner_gain')
        else
          check!(rtlsdr_set_tuner_gain_mode(dev, 0), 'gain_mode auto')
          rtlsdr_set_agc_mode(dev, 1)
        end
        check!(rtlsdr_reset_buffer(dev), 'reset_buffer')
        true
      end

      # Supported Method Parameters::
      # iq_u8 = PWN::FFI::RTLSdr.read_sync(
      #   device: 'required - pointer from .open',
      #   bytes:  'optional - number of raw bytes to read (default 262144)'
      # )
      # Returns a binary String of unsigned 8-bit interleaved I/Q samples.

      public_class_method def self.read_sync(opts = {})
        dev = opts[:device]
        raise 'ERROR: :device required' if dev.nil? || dev.null?

        nbytes = (opts[:bytes] || 262_144).to_i
        buf = PubFFI::MemoryPointer.new(:uint8, nbytes)
        n_read = PubFFI::MemoryPointer.new(:int)
        rc = rtlsdr_read_sync(dev, buf, nbytes, n_read)
        raise "ERROR: rtlsdr_read_sync rc=#{rc}" unless rc.zero?

        got = n_read.read_int
        buf.read_string(got)
      end

      # Supported Method Parameters::
      # gains = PWN::FFI::RTLSdr.tuner_gains(device: pointer)
      # Returns Array<Integer> of supported gains in tenths of a dB.

      public_class_method def self.tuner_gains(opts = {})
        dev = opts[:device]
        raise 'ERROR: :device required' if dev.nil? || dev.null?

        n = rtlsdr_get_tuner_gains(dev, nil)
        return [] if n <= 0

        ptr = PubFFI::MemoryPointer.new(:int, n)
        rtlsdr_get_tuner_gains(dev, ptr)
        ptr.read_array_of_int(n)
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.available?
          #{self}.list_devices
          dev = #{self}.open(index: 0)
          #{self}.configure(device: dev, freq_hz:, rate_hz: 2_048_000, gain_db: nil, ppm: 0)
          #{self}.tuner_gains(device: dev)
          iq = #{self}.read_sync(device: dev, bytes: 262_144)  # u8 I/Q String
          #{self}.close(device: dev)

          #{self}.authors
        "
      end

      class << self
        private

        def check!(code, what)
          raise "ERROR: rtlsdr_#{what} rc=#{code}" unless code.zero? || code.positive?
        end
      end
    end
  end
end
