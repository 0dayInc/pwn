# frozen_string_literal: true

require 'ffi'

PubFFI = ::FFI unless defined?(PubFFI) # rubocop:disable Style/RedundantConstantBase

module PWN
  module FFI
    # Thin VOLK (Vector-Optimized Library of Kernels) binding.
    #
    # Dispatches to SIMD kernels (SSE/AVX/NEON/…) when the host provides them.
    # Used by PWN::SDR::Decoder::DSP hot paths so MHz-rate I/Q work stays
    # off the Ruby GC heap while orchestration remains pure Ruby.
    #
    # Nothing here shells out and nothing is compiled at gem-install time —
    # if libvolk is missing, `.available?` is false and callers fall back.
    module Volk
      extend PubFFI::Library

      @load_error = nil
      begin
        ffi_lib %w[volk libvolk.so.3.3 libvolk.so.3 libvolk.so]
      rescue LoadError => e
        @load_error = e
      end

      class << self
        attr_reader :load_error
      end

      unless @load_error
        # Memory helpers (always present as T symbols)
        attach_function :volk_get_alignment, [], :size_t
        attach_function :volk_malloc, %i[size_t size_t], :pointer
        attach_function :volk_free, [:pointer], :void

        # VOLK dispatches are *data* symbols (function pointers). Bind them
        # with attach_variable then wrap in FFI::Function on first use so we
        # always hit the CPU-tuned kernel selected by the dispatcher.
        attach_variable :volk_16i_s32f_convert_32f, :pointer
        attach_variable :volk_32f_accumulator_s32f, :pointer
        attach_variable :volk_32fc_magnitude_squared_32f, :pointer
        attach_variable :volk_32f_sqrt_32f, :pointer
        attach_variable :volk_32f_s32f_multiply_32f, :pointer
        attach_variable :volk_32f_x2_dot_prod_32f, :pointer
      end

      # Supported Method Parameters::
      # PWN::FFI::Volk.available?

      public_class_method def self.available?
        !@load_error && respond_to?(:volk_get_alignment, true)
      rescue StandardError
        false
      end

      # Supported Method Parameters::
      # samples = PWN::FFI::Volk.unpack_s16le(
      #   data: 'required - raw String of little-endian signed 16-bit PCM'
      # )
      # Returns Array<Float> normalised to -1.0..1.0 (same contract as
      # PWN::SDR::Decoder::DSP.unpack_s16le). VOLK treats `scalar` as a
      # divisor, so pass 32768.0 to get unit-range floats.

      public_class_method def self.unpack_s16le(opts = {})
        raise 'ERROR: libvolk not available' unless available?

        data = opts[:data].to_s
        n = data.bytesize / 2
        return [] if n.zero?

        in_ptr = PubFFI::MemoryPointer.from_string(data)
        # from_string null-terminates — reclaim only the payload region
        out_ptr = PubFFI::MemoryPointer.new(:float, n)
        convert_fn.call(out_ptr, in_ptr, 32_768.0, n)
        out_ptr.read_array_of_float(n)
      end

      # Supported Method Parameters::
      # sum = PWN::FFI::Volk.accumulate(samples: Array<Float>)

      public_class_method def self.accumulate(opts = {})
        raise 'ERROR: libvolk not available' unless available?

        samples = opts[:samples]
        n = samples.length
        return 0.0 if n.zero?

        in_ptr = float_ptr(samples)
        out_ptr = PubFFI::MemoryPointer.new(:float, 1)
        accum_fn.call(out_ptr, in_ptr, n)
        out_ptr.read_float
      end

      # Supported Method Parameters::
      # power = PWN::FFI::Volk.magnitude_squared(
      #   iq: 'required - Array of interleaved I/Q Floats (even length)'
      # )
      # Returns Array<Float> of |z|^2 per complex sample.

      public_class_method def self.magnitude_squared(opts = {})
        raise 'ERROR: libvolk not available' unless available?

        iq = opts[:iq]
        n_c = iq.length / 2
        return [] if n_c.zero?

        in_ptr = float_ptr(iq)
        out_ptr = PubFFI::MemoryPointer.new(:float, n_c)
        mag2_fn.call(out_ptr, in_ptr, n_c)
        out_ptr.read_array_of_float(n_c)
      end

      # Supported Method Parameters::
      # out = PWN::FFI::Volk.sqrt(samples: Array<Float>)

      public_class_method def self.sqrt(opts = {})
        raise 'ERROR: libvolk not available' unless available?

        samples = opts[:samples]
        n = samples.length
        return [] if n.zero?

        in_ptr = float_ptr(samples)
        out_ptr = PubFFI::MemoryPointer.new(:float, n)
        sqrt_fn.call(out_ptr, in_ptr, n)
        out_ptr.read_array_of_float(n)
      end

      # Supported Method Parameters::
      # out = PWN::FFI::Volk.scale(samples: Array<Float>, factor: Float)
      # Multiplies every sample by factor.

      public_class_method def self.scale(opts = {})
        raise 'ERROR: libvolk not available' unless available?

        samples = opts[:samples]
        factor  = opts[:factor].to_f
        n = samples.length
        return [] if n.zero?

        in_ptr = float_ptr(samples)
        out_ptr = PubFFI::MemoryPointer.new(:float, n)
        scale_fn.call(out_ptr, in_ptr, factor, n)
        out_ptr.read_array_of_float(n)
      end

      # Supported Method Parameters::
      # sum = PWN::FFI::Volk.dot_prod(a: Array<Float>, b: Array<Float>)

      public_class_method def self.dot_prod(opts = {})
        raise 'ERROR: libvolk not available' unless available?

        a = opts[:a]
        b = opts[:b]
        n = [a.length, b.length].min
        return 0.0 if n.zero?

        a_ptr = float_ptr(a)
        b_ptr = float_ptr(b)
        out_ptr = PubFFI::MemoryPointer.new(:float, 1)
        dot_fn.call(out_ptr, a_ptr, b_ptr, n)
        out_ptr.read_float
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.available?                           # => true/false
          #{self}.unpack_s16le(data: raw_bytes)        # s16le → Float[-1,1]
          #{self}.accumulate(samples:)                 # Σ samples
          #{self}.magnitude_squared(iq:)               # |z|² per complex pair
          #{self}.sqrt(samples:)
          #{self}.scale(samples:, factor:)
          #{self}.dot_prod(a:, b:)

          #{self}.authors
        "
      end

      class << self
        private

        def float_ptr(arr)
          ptr = PubFFI::MemoryPointer.new(:float, arr.length)
          ptr.write_array_of_float(arr.map(&:to_f))
          ptr
        end

        def convert_fn
          @convert_fn ||= PubFFI::Function.new(
            :void, %i[pointer pointer float uint],
            volk_16i_s32f_convert_32f
          )
        end

        def accum_fn
          @accum_fn ||= PubFFI::Function.new(
            :void, %i[pointer pointer uint],
            volk_32f_accumulator_s32f
          )
        end

        def mag2_fn
          @mag2_fn ||= PubFFI::Function.new(
            :void, %i[pointer pointer uint],
            volk_32fc_magnitude_squared_32f
          )
        end

        def sqrt_fn
          @sqrt_fn ||= PubFFI::Function.new(
            :void, %i[pointer pointer uint],
            volk_32f_sqrt_32f
          )
        end

        def scale_fn
          @scale_fn ||= PubFFI::Function.new(
            :void, %i[pointer pointer float uint],
            volk_32f_s32f_multiply_32f
          )
        end

        def dot_fn
          @dot_fn ||= PubFFI::Function.new(
            :void, %i[pointer pointer pointer uint],
            volk_32f_x2_dot_prod_32f
          )
        end
      end
    end
  end
end
