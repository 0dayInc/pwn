# frozen_string_literal: true

require 'ffi'

# Top-level alias so PWN::FFI::* modules can `extend PubFFI::Library`
# without the PWN::FFI ↔ ::FFI (gem) namespace collision. Every binding
# under lib/pwn/ffi/*.rb reuses this — define exactly once.
PubFFI = ::FFI unless defined?(PubFFI) # rubocop:disable Style/RedundantConstantBase

module PWN
  # This file, using the autoload directive loads FFI modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  #
  # Bindings under this namespace are *thin* — they attach functions from
  # already-installed system shared objects (libliquid, libvolk, libfftw3f,
  # librtlsdr, libhackrf, libSoapySDR) so PWN::SDR::Decoder::* can run
  # MHz-rate DSP inner loops in native/SIMD code while Ruby stays in charge
  # of orchestration. Nothing here shells out; nothing here compiles at
  # `gem install` time. If a .so is missing the module still loads and
  # `.available?` returns false so callers can fall back to pure Ruby.
  module FFI
    autoload :AdalmPluto, 'pwn/ffi/adalm_pluto'
    autoload :FFTW,     'pwn/ffi/fftw'
    autoload :HackRF,   'pwn/ffi/hack_rf'
    autoload :Liquid,   'pwn/ffi/liquid'
    autoload :RTLSdr,   'pwn/ffi/rtl_sdr'
    autoload :SoapySDR, 'pwn/ffi/soapy_sdr'
    autoload :Stdio,    'pwn/ffi/stdio'
    autoload :Volk,     'pwn/ffi/volk'

    # Supported Method Parameters::
    # ok = PWN::FFI.available?(
    #   mod: 'required - Symbol or Module (e.g. :Liquid or PWN::FFI::Liquid)'
    # )

    public_class_method def self.available?(opts = {})
      mod = opts[:mod]
      mod = const_get(mod) if mod.is_a?(Symbol) || mod.is_a?(String)
      mod.respond_to?(:available?) && mod.available?
    rescue NameError, LoadError
      false
    end

    # Supported Method Parameters::
    # PWN::FFI.backends
    # Returns { ModuleName => true|false } for every registered binding.

    public_class_method def self.backends
      (constants - [:Stdio]).sort.to_h { |c| [c, available?(mod: c)] }
    end

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    # Display a List of Every PWN::FFI Module

    public_class_method def self.help
      constants.sort
    end
  end
end
