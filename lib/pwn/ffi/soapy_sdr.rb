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
    # Full streaming can be layered later; today this is the discovery
    # surface. Missing lib → `.available?` false, pure-Ruby / CLI fallbacks.
    module SoapySDR
      extend PubFFI::Library

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

          #{self}.authors
        "
      end
    end
  end
end
