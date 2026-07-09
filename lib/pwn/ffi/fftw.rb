# frozen_string_literal: true

require 'ffi'

PubFFI = ::FFI unless defined?(PubFFI) # rubocop:disable Style/RedundantConstantBase

module PWN
  module FFI
    # Thin single-precision FFTW3 binding (`libfftw3f`).
    #
    # Used by PWN::SDR::* spectrum work (GQRX FFT snapshots, wideband energy
    # detectors) when MHz-rate FFTs outgrow pure-Ruby DFT. Missing library
    # degrades cleanly via `.available?` — callers keep pure-Ruby fallbacks.
    #
    # No compile step at gem install; no shells. Plans are built with
    # FFTW_ESTIMATE so first-call latency stays acceptable for REPL use.
    module FFTW
      extend PubFFI::Library

      FFTW_ESTIMATE = (1 << 6)
      FFTW_MEASURE  = 0
      FFTW_FORWARD  = -1
      FFTW_BACKWARD = 1

      @load_error = nil
      begin
        ffi_lib %w[fftw3f libfftw3f.so.3 libfftw3f.so]
      rescue LoadError => e
        @load_error = e
      end

      class << self
        attr_reader :load_error
      end

      unless @load_error
        # fftwf_complex is float[2] (re, im) under the C ABI we target.
        attach_function :fftwf_malloc, [:size_t], :pointer
        attach_function :fftwf_free, [:pointer], :void
        attach_function :fftwf_destroy_plan, [:pointer], :void
        attach_function :fftwf_cleanup, [], :void
        attach_function :fftwf_execute, [:pointer], :void

        # Real → complex 1-D (out has n/2+1 complex bins = 2*(n/2+1) floats)
        attach_function :fftwf_plan_dft_r2c_1d,
                        %i[int pointer pointer uint],
                        :pointer

        # Complex → real 1-D
        attach_function :fftwf_plan_dft_c2r_1d,
                        %i[int pointer pointer uint],
                        :pointer

        # Complex ↔ complex 1-D
        attach_function :fftwf_plan_dft_1d,
                        %i[int pointer pointer int uint],
                        :pointer
      end

      # Supported Method Parameters::
      # PWN::FFI::FFTW.available?

      public_class_method def self.available?
        !@load_error && respond_to?(:fftwf_malloc, true)
      rescue StandardError
        false
      end

      # Supported Method Parameters::
      # spectrum = PWN::FFI::FFTW.rfft(
      #   samples: 'required - Array<Float> real input (length = n)',
      #   n:       'optional - FFT size (default samples.length; zero-pads/truncates)'
      # )
      # Returns Array of [re, im] pairs, length n/2+1 (DC .. Nyquist).

      public_class_method def self.rfft(opts = {})
        raise 'ERROR: libfftw3f not available' unless available?

        samples = opts[:samples]
        n = (opts[:n] || samples.length).to_i
        raise 'ERROR: n must be >= 1' if n < 1

        in_ptr = fftwf_malloc(n * 4)
        out_bins = (n / 2) + 1
        out_ptr = fftwf_malloc(out_bins * 2 * 4)
        raise 'ERROR: fftwf_malloc failed' if in_ptr.null? || out_ptr.null?

        # zero + copy
        in_ptr.write_array_of_float(Array.new(n, 0.0))
        src = samples.first([n, samples.length].min).map(&:to_f)
        in_ptr.write_array_of_float(src + Array.new(n - src.length, 0.0)) if src.length < n
        in_ptr.write_array_of_float(src) if src.length == n

        plan = fftwf_plan_dft_r2c_1d(n, in_ptr, out_ptr, FFTW_ESTIMATE)
        raise 'ERROR: fftwf_plan_dft_r2c_1d failed' if plan.null?

        fftwf_execute(plan)
        flat = out_ptr.read_array_of_float(out_bins * 2)
        result = Array.new(out_bins) { |i| [flat[2 * i], flat[(2 * i) + 1]] }

        fftwf_destroy_plan(plan)
        fftwf_free(in_ptr)
        fftwf_free(out_ptr)
        result
      end

      # Supported Method Parameters::
      # mag = PWN::FFI::FFTW.rfft_magnitude(
      #   samples: 'required - Array<Float>',
      #   n:       'optional - FFT size'
      # )
      # Returns Array<Float> of |X[k]| for k=0..n/2.

      public_class_method def self.rfft_magnitude(opts = {})
        rfft(opts).map { |re, im| Math.sqrt((re * re) + (im * im)) }
      end

      # Supported Method Parameters::
      # power_db = PWN::FFI::FFTW.rfft_power_db(
      #   samples: 'required - Array<Float>',
      #   n:       'optional - FFT size',
      #   floor:   'optional - dB floor for zeros (default -120.0)'
      # )
      # Returns Array<Float> of 20*log10(|X[k]|) with a noise floor.

      public_class_method def self.rfft_power_db(opts = {})
        floor = (opts[:floor] || -120.0).to_f
        rfft_magnitude(opts).map do |m|
          m.positive? ? (20.0 * Math.log10(m)) : floor
        end
      end

      # Supported Method Parameters::
      # spectrum = PWN::FFI::FFTW.cfft(
      #   iq:   'required - interleaved Array<Float> I/Q (even length)',
      #   n:    'optional - number of complex samples (default iq.length/2)',
      #   sign: 'optional - :forward (default) or :backward'
      # )
      # Returns Array of [re, im] pairs length n.

      public_class_method def self.cfft(opts = {})
        raise 'ERROR: libfftw3f not available' unless available?

        iq = opts[:iq]
        n = (opts[:n] || (iq.length / 2)).to_i
        raise 'ERROR: n must be >= 1' if n < 1

        sign = opts[:sign] == :backward ? FFTW_BACKWARD : FFTW_FORWARD
        bytes = n * 2 * 4
        in_ptr = fftwf_malloc(bytes)
        out_ptr = fftwf_malloc(bytes)
        raise 'ERROR: fftwf_malloc failed' if in_ptr.null? || out_ptr.null?

        src = iq.first([2 * n, iq.length].min).map(&:to_f)
        padded = src + Array.new((2 * n) - src.length, 0.0)
        in_ptr.write_array_of_float(padded)

        plan = fftwf_plan_dft_1d(n, in_ptr, out_ptr, sign, FFTW_ESTIMATE)
        raise 'ERROR: fftwf_plan_dft_1d failed' if plan.null?

        fftwf_execute(plan)
        flat = out_ptr.read_array_of_float(n * 2)
        result = Array.new(n) { |i| [flat[2 * i], flat[(2 * i) + 1]] }

        fftwf_destroy_plan(plan)
        fftwf_free(in_ptr)
        fftwf_free(out_ptr)
        result
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.available?                         # => true/false
          #{self}.rfft(samples:, n: nil)             # real→complex, [[re,im],…]
          #{self}.rfft_magnitude(samples:, n: nil)   # |X[k]|
          #{self}.rfft_power_db(samples:, n:, floor: -120.0)
          #{self}.cfft(iq:, n: nil, sign: :forward)  # complex FFT

          #{self}.authors
        "
      end
    end
  end
end
