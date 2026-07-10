# frozen_string_literal: true

require 'ffi'

PubFFI = ::FFI unless defined?(PubFFI) # rubocop:disable Style/RedundantConstantBase

module PWN
  module FFI
    # Thin SoapySDR C-API binding (libSoapySDR). Inventory-focused first —
    # enumerate devices and report API version so Extrospection `probe_rf`
    # can list every Soapy-backed front-end (RTL-SDR, HackRF, Airspy,
    # Pluto, UHD, …) without shelling out to `SoapySDRUtil`.
    #
    # Streaming: open/configure/start_rx/read_sync/stop_rx/close for CS16
    # I/Q so PWN::SDR::Decoder::Base.run_iq can true-air decode from ANY
    # Soapy-backed front-end. Missing lib -> .available? false, callers
    # fall back to pure Ruby / other PWN::FFI front-ends.
    module SoapySDR
      extend PubFFI::Library

      SOAPY_SDR_RX   = 1
      SOAPY_SDR_CS16 = 'CS16'

      @load_error = nil
      begin
        ffi_lib %w[SoapySDR libSoapySDR.so.0.8 libSoapySDR.so.0 libSoapySDR.so]
      rescue LoadError => e
        @load_error = e
      end

      class << self
        attr_reader :load_error
      end

      # SoapySDRKwargs is {size_t size; char** keys; char** vals;}
      class Kwargs < PubFFI::Struct
        layout :size, :size_t,
               :keys, :pointer,
               :vals, :pointer
      end

      unless @load_error
        attach_function :SoapySDR_getAPIVersion, [], :string
        attach_function :SoapySDR_getABIVersion, [], :string
        attach_function :SoapySDR_getLibVersion, [], :string

        # SoapySDRKwargs* SoapySDRDevice_enumerate(const SoapySDRKwargs* args, size_t* length)
        attach_function :SoapySDRDevice_enumerate,
                        %i[pointer pointer],
                        :pointer

        # void SoapySDRKwargsList_clear(SoapySDRKwargs *kwargs, size_t length)
        attach_function :SoapySDRKwargsList_clear,
                        %i[pointer size_t],
                        :void

        # SoapySDRDevice* SoapySDRDevice_make(const SoapySDRKwargs* args)
        attach_function :SoapySDRDevice_make, [:pointer], :pointer
        # SoapySDRDevice* SoapySDRDevice_makeStrArgs(const char* args)
        attach_function :SoapySDRDevice_makeStrArgs, [:string], :pointer
        attach_function :SoapySDRDevice_unmake, [:pointer], :int
        attach_function :SoapySDRDevice_getDriverKey, [:pointer], :string
        attach_function :SoapySDRDevice_getHardwareKey, [:pointer], :string

        attach_function :SoapySDRDevice_setSampleRate, %i[pointer int size_t double], :int
        attach_function :SoapySDRDevice_setFrequency,
                        %i[pointer int size_t double pointer], :int
        attach_function :SoapySDRDevice_setGain, %i[pointer int size_t double], :int
        attach_function :SoapySDRDevice_setGainMode, %i[pointer int size_t bool], :int
        attach_function :SoapySDRDevice_setBandwidth, %i[pointer int size_t double], :int

        # SoapySDR 0.8 signature: returns SoapySDRStream*
        attach_function :SoapySDRDevice_setupStream,
                        %i[pointer int string pointer size_t pointer], :pointer
        attach_function :SoapySDRDevice_activateStream,
                        %i[pointer pointer int long_long size_t], :int
        attach_function :SoapySDRDevice_readStream,
                        %i[pointer pointer pointer size_t pointer pointer long],
                        :int, blocking: true
        attach_function :SoapySDRDevice_deactivateStream,
                        %i[pointer pointer int long_long], :int
        attach_function :SoapySDRDevice_closeStream, %i[pointer pointer], :int
        attach_function :SoapySDRDevice_getStreamMTU, %i[pointer pointer], :size_t
        attach_function :SoapySDRDevice_lastError, [], :string
        # char* SoapySDRDevice_getHardwareInfo — returns freeable dict as string? skip
      end

      # Supported Method Parameters::
      # PWN::FFI::SoapySDR.available?

      public_class_method def self.available?
        !@load_error && respond_to?(:SoapySDR_getAPIVersion, true)
      rescue StandardError
        false
      end

      # Supported Method Parameters::
      # info = PWN::FFI::SoapySDR.info
      # Returns { available:, api:, abi:, lib: }.

      public_class_method def self.info
        return { available: false, error: @load_error&.message } unless available?

        {
          available: true,
          api: SoapySDR_getAPIVersion().to_s,
          abi: SoapySDR_getABIVersion().to_s,
          lib: SoapySDR_getLibVersion().to_s
        }
      end

      # Supported Method Parameters::
      # devices = PWN::FFI::SoapySDR.list_devices
      # Returns Array<Hash> of keyword→value maps for every enumerated device.

      public_class_method def self.list_devices
        raise 'ERROR: libSoapySDR not available' unless available?

        len_ptr = PubFFI::MemoryPointer.new(:size_t)
        # pass NULL args → enumerate everything
        list_ptr = SoapySDRDevice_enumerate(nil, len_ptr)
        length = len_ptr.read_ulong
        return [] if list_ptr.null? || length.zero?

        results = []
        length.times do |i|
          kw = Kwargs.new(list_ptr + (i * Kwargs.size))
          h = {}
          kw[:size].times do |j|
            key = kw[:keys].get_pointer(j * PubFFI::Pointer.size)
            val = kw[:vals].get_pointer(j * PubFFI::Pointer.size)
            h[key.read_string.to_sym] = val.read_string unless key.null?
          end
          results << h
        end
        SoapySDRKwargsList_clear(list_ptr, length)
        results
      end

      # Supported Method Parameters::
      # dev = PWN::FFI::SoapySDR.make(args: 'driver=rtlsdr')
      # Returns opaque pointer (SoapySDRDevice*) or raises.
      # ALWAYS pair with .unmake.

      public_class_method def self.make(opts = {})
        raise 'ERROR: libSoapySDR not available' unless available?

        args = opts[:args].to_s
        dev = SoapySDRDevice_makeStrArgs(args)
        raise "ERROR: SoapySDRDevice_makeStrArgs(#{args.inspect}) returned NULL" if dev.null?

        dev
      end

      # Supported Method Parameters::
      # PWN::FFI::SoapySDR.unmake(device: pointer)

      public_class_method def self.unmake(opts = {})
        dev = opts[:device]
        return unless dev && !dev.null?

        SoapySDRDevice_unmake(dev)
        nil
      end

      # Supported Method Parameters::
      # meta = PWN::FFI::SoapySDR.device_keys(device: pointer)
      # Returns { driver:, hardware: }.

      public_class_method def self.device_keys(opts = {})
        dev = opts[:device]
        raise 'ERROR: :device required' if dev.nil? || dev.null?

        {
          driver: SoapySDRDevice_getDriverKey(dev).to_s,
          hardware: SoapySDRDevice_getHardwareKey(dev).to_s
        }
      end
      # Supported Method Parameters::
      # h = PWN::FFI::SoapySDR.open(
      #   args:    'optional - Soapy args string, e.g. "driver=rtlsdr"',
      #   channel: 'optional - RX channel (default 0)'
      # )
      # Convenience wrapper around .make; returns { device:, channel: }.

      public_class_method def self.open(opts = {})
        args = opts[:args].to_s
        args = list_devices.first&.map { |k, v| "#{k}=#{v}" }&.join(',').to_s if args.empty?
        raise 'ERROR: no SoapySDR devices found' if args.empty?

        { device: make(args: args), args: args, channel: (opts[:channel] || 0).to_i }
      end

      # Supported Method Parameters::
      # PWN::FFI::SoapySDR.configure(
      #   handle:   'required - from .open',
      #   freq_hz:  'required - center frequency Hz',
      #   rate_hz:  'optional - sample rate Hz (default 2_048_000)',
      #   gain_db:  'optional - overall gain dB (default AGC on)',
      #   bw_hz:    'optional - baseband filter BW Hz'
      # )

      public_class_method def self.configure(opts = {}) # rubocop:disable Naming/PredicateMethod
        h = opts[:handle]
        raise 'ERROR: :handle required (from .open)' unless h.is_a?(Hash) && h[:device]

        dev  = h[:device]
        ch   = h[:channel]
        rate = (opts[:rate_hz] || 2_048_000).to_f
        freq = opts[:freq_hz].to_f
        SoapySDRDevice_setSampleRate(dev, SOAPY_SDR_RX, ch, rate)
        SoapySDRDevice_setFrequency(dev, SOAPY_SDR_RX, ch, freq, nil)
        if opts[:gain_db]
          SoapySDRDevice_setGainMode(dev, SOAPY_SDR_RX, ch, false)
          SoapySDRDevice_setGain(dev, SOAPY_SDR_RX, ch, opts[:gain_db].to_f)
        else
          SoapySDRDevice_setGainMode(dev, SOAPY_SDR_RX, ch, true)
        end
        SoapySDRDevice_setBandwidth(dev, SOAPY_SDR_RX, ch, opts[:bw_hz].to_f) if opts[:bw_hz]
        h[:rate_hz] = rate.to_i
        h[:freq_hz] = freq.to_i
        true
      end

      # Supported Method Parameters::
      # PWN::FFI::SoapySDR.start_rx(
      #   handle:  'required - from .open',
      #   samples: 'optional - MTU / read block size (default 65536)'
      # )
      # Sets up + activates a CS16 RX stream. Extends handle in place.

      public_class_method def self.start_rx(opts = {})
        h = opts[:handle]
        raise 'ERROR: :handle required (from .open)' unless h.is_a?(Hash) && h[:device]

        dev = h[:device]
        ch  = h[:channel]
        chan_ptr = PubFFI::MemoryPointer.new(:size_t, 1)
        chan_ptr.write_ulong(ch)
        stream = SoapySDRDevice_setupStream(dev, SOAPY_SDR_RX, SOAPY_SDR_CS16, chan_ptr, 1, nil)
        raise "ERROR: setupStream failed: #{SoapySDRDevice_lastError()}" if stream.nil? || stream.null?

        rc = SoapySDRDevice_activateStream(dev, stream, 0, 0, 0)
        raise "ERROR: activateStream rc=#{rc}: #{SoapySDRDevice_lastError()}" if rc.nonzero?

        mtu   = SoapySDRDevice_getStreamMTU(dev, stream)
        elems = (opts[:samples] || (mtu.positive? ? mtu : 65_536)).to_i
        # CS16 = 2x int16 per sample = 4 bytes per element
        buf   = PubFFI::MemoryPointer.new(:int8, elems * 4)
        buffs = PubFFI::MemoryPointer.new(:pointer, 1)
        buffs.write_pointer(buf)
        h.merge!(
          stream: stream, buf: buf, buffs: buffs, elems: elems,
          flags_p: PubFFI::MemoryPointer.new(:int),
          time_p: PubFFI::MemoryPointer.new(:long_long),
          format: :cs16
        )
        h
      end

      # Supported Method Parameters::
      # data = PWN::FFI::SoapySDR.read_sync(
      #   handle:     'required - from .start_rx',
      #   timeout_us: 'optional - microseconds (default 1_000_000)'
      # )
      # Returns String of interleaved cs16le I/Q (4 bytes/sample), or nil.

      public_class_method def self.read_sync(opts = {})
        h = opts[:handle]
        raise 'ERROR: :handle required (from .start_rx)' unless h.is_a?(Hash) && h[:stream]

        to = (opts[:timeout_us] || 1_000_000).to_i
        n = SoapySDRDevice_readStream(
          h[:device], h[:stream], h[:buffs], h[:elems], h[:flags_p], h[:time_p], to
        )
        return nil if n <= 0

        h[:buf].read_bytes(n * 4)
      end

      # Supported Method Parameters::
      # PWN::FFI::SoapySDR.stop_rx(handle: h)

      public_class_method def self.stop_rx(opts = {})
        h = opts[:handle]
        return unless h.is_a?(Hash) && h[:stream]

        SoapySDRDevice_deactivateStream(h[:device], h[:stream], 0, 0)
        SoapySDRDevice_closeStream(h[:device], h[:stream])
        h[:stream] = nil
        nil
      rescue StandardError
        nil
      end

      # Supported Method Parameters::
      # PWN::FFI::SoapySDR.close(handle: h)

      public_class_method def self.close(opts = {})
        h = opts[:handle]
        return unmake(device: opts[:device]) if opts[:device]
        return unless h.is_a?(Hash) && h[:device]

        stop_rx(handle: h) if h[:stream]
        unmake(device: h[:device])
        h[:device] = nil
        nil
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
          #{self}.list_devices
          dev = #{self}.make(args: 'driver=rtlsdr')
          #{self}.device_keys(device: dev)
          #{self}.unmake(device: dev)

          h = #{self}.open(args: 'driver=rtlsdr')
          #{self}.configure(handle: h, freq_hz:, rate_hz: 2_048_000, gain_db: nil)
          #{self}.start_rx(handle: h)
          data = #{self}.read_sync(handle: h)   # cs16le interleaved I/Q
          #{self}.stop_rx(handle: h)
          #{self}.close(handle: h)

          #{self}.authors
        "
      end
    end
  end
end
