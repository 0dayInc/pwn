# frozen_string_literal: true

require 'ffi'

PubFFI = ::FFI unless defined?(PubFFI) # rubocop:disable Style/RedundantConstantBase

module PWN
  module FFI
    # Thin liquid-dsp binding.
    #
    # Provides the high-level DSP building blocks that PWN::SDR::Decoder::*
    # needs beyond pure-Ruby primitives: FM / frequency demodulation,
    # multi-stage arbitrary resampling, and Kaiser FIR filters. Opaque
    # liquid handles are held as FFI::Pointer and always freed in an
    # ensure — no compile step, no shells. If libliquid is absent
    # `.available?` is false and DSP falls back to pure Ruby.
    #
    # Complex samples use the GCC float _Complex ABI: interleaved
    # float[2] (re, im) per sample, which is how liquid_float_complex is
    # laid out under LIQUID_DEFINE_COMPLEX.
    module Liquid
      extend PubFFI::Library

      @load_error = nil
      begin
        ffi_lib %w[liquid libliquid.so.1 libliquid.so]
      rescue LoadError => e
        @load_error = e
      end

      class << self
        attr_reader :load_error
      end

      unless @load_error
        # ── freqdem (analog FM / frequency demodulator) ────────────────
        attach_function :freqdem_create, [:float], :pointer
        attach_function :freqdem_destroy, [:pointer], :int
        attach_function :freqdem_reset, [:pointer], :int
        attach_function :freqdem_print, [:pointer], :int
        attach_function :freqdem_demodulate_block,
                        %i[pointer pointer uint pointer],
                        :int

        # ── msresamp_rrrf (multi-stage arbitrary real resampler) ───────
        attach_function :msresamp_rrrf_create, %i[float float], :pointer
        attach_function :msresamp_rrrf_destroy, [:pointer], :int
        attach_function :msresamp_rrrf_reset, [:pointer], :int
        attach_function :msresamp_rrrf_get_rate, [:pointer], :float
        attach_function :msresamp_rrrf_get_delay, [:pointer], :float
        attach_function :msresamp_rrrf_get_num_output, %i[pointer uint], :uint
        attach_function :msresamp_rrrf_execute,
                        %i[pointer pointer uint pointer pointer],
                        :int

        # ── firfilt_rrrf (real FIR filter) ─────────────────────────────
        attach_function :firfilt_rrrf_create_kaiser,
                        %i[uint float float float],
                        :pointer
        attach_function :firfilt_rrrf_create_dc_blocker,
                        %i[uint float],
                        :pointer
        attach_function :firfilt_rrrf_destroy, [:pointer], :int
        attach_function :firfilt_rrrf_reset, [:pointer], :int
        attach_function :firfilt_rrrf_execute_block,
                        %i[pointer pointer uint pointer],
                        :int
      end

      # Supported Method Parameters::
      # PWN::FFI::Liquid.available?

      public_class_method def self.available?
        !@load_error && respond_to?(:freqdem_create, true)
      rescue StandardError
        false
      end

      # Supported Method Parameters::
      # audio = PWN::FFI::Liquid.freq_demod(
      #   iq: 'required - interleaved I/Q Array<Float> (even length)',
      #   kf: 'optional - modulation factor (default 0.5)'
      # )
      # Returns Array<Float> of demodulated real samples (length = iq.length/2).

      public_class_method def self.freq_demod(opts = {})
        raise 'ERROR: libliquid not available' unless available?

        iq = opts[:iq]
        kf = (opts[:kf] || 0.5).to_f
        n  = iq.length / 2
        return [] if n.zero?

        fd = freqdem_create(kf)
        raise 'ERROR: freqdem_create failed' if fd.null?

        begin
          in_ptr = float_ptr(iq.first(n * 2))
          out_ptr = PubFFI::MemoryPointer.new(:float, n)
          rc = freqdem_demodulate_block(fd, in_ptr, n, out_ptr)
          raise "ERROR: freqdem_demodulate_block rc=#{rc}" unless rc.zero?

          out_ptr.read_array_of_float(n)
        ensure
          freqdem_destroy(fd)
        end
      end

      # Supported Method Parameters::
      # out = PWN::FFI::Liquid.resample(
      #   samples:  'required - Array<Float>',
      #   rate:     'required - output/input ratio (>0)',
      #   as_db:    'optional - stop-band attenuation dB (default 60.0)'
      # )
      # Returns Array<Float> of resampled samples.

      public_class_method def self.resample(opts = {})
        raise 'ERROR: libliquid not available' unless available?

        samples = opts[:samples]
        rate    = opts[:rate].to_f
        as_db   = (opts[:as_db] || 60.0).to_f
        raise 'ERROR: rate must be > 0' unless rate.positive?
        return samples.dup if samples.empty?

        q = msresamp_rrrf_create(rate, as_db)
        raise 'ERROR: msresamp_rrrf_create failed' if q.null?

        begin
          nx = samples.length
          # allocate generously: ceil(1 + 2*r*nx)
          ny_max = [1, (1 + (2 * rate * nx)).ceil].max
          in_ptr = float_ptr(samples)
          out_ptr = PubFFI::MemoryPointer.new(:float, ny_max)
          ny_ptr = PubFFI::MemoryPointer.new(:uint, 1)
          rc = msresamp_rrrf_execute(q, in_ptr, nx, out_ptr, ny_ptr)
          raise "ERROR: msresamp_rrrf_execute rc=#{rc}" unless rc.zero?

          ny = ny_ptr.read_uint
          out_ptr.read_array_of_float(ny)
        ensure
          msresamp_rrrf_destroy(q)
        end
      end

      # Supported Method Parameters::
      # out = PWN::FFI::Liquid.fir_kaiser(
      #   samples: 'required - Array<Float>',
      #   length:  'optional - filter length (default 51, odd preferred)',
      #   fc:      'optional - normalised cutoff 0..0.5 (default 0.1)',
      #   as_db:   'optional - stop-band attenuation dB (default 60.0)',
      #   mu:      'optional - fractional sample offset (default 0.0)'
      # )
      # Returns Array<Float> same length as input.

      public_class_method def self.fir_kaiser(opts = {})
        raise 'ERROR: libliquid not available' unless available?

        samples = opts[:samples]
        length  = (opts[:length] || 51).to_i
        fc      = (opts[:fc] || 0.1).to_f
        as_db   = (opts[:as_db] || 60.0).to_f
        mu      = (opts[:mu] || 0.0).to_f
        return [] if samples.empty?

        q = firfilt_rrrf_create_kaiser(length, fc, as_db, mu)
        raise 'ERROR: firfilt_rrrf_create_kaiser failed' if q.null?

        begin
          n = samples.length
          in_ptr = float_ptr(samples)
          out_ptr = PubFFI::MemoryPointer.new(:float, n)
          rc = firfilt_rrrf_execute_block(q, in_ptr, n, out_ptr)
          raise "ERROR: firfilt_rrrf_execute_block rc=#{rc}" unless rc.zero?

          out_ptr.read_array_of_float(n)
        ensure
          firfilt_rrrf_destroy(q)
        end
      end

      # Supported Method Parameters::
      # out = PWN::FFI::Liquid.dc_block(
      #   samples: 'required - Array<Float>',
      #   m:       'optional - prototype semi-length (default 7 → len 15)',
      #   as_db:   'optional - stop-band attenuation dB (default 60.0)'
      # )

      public_class_method def self.dc_block(opts = {})
        raise 'ERROR: libliquid not available' unless available?

        samples = opts[:samples]
        m       = (opts[:m] || 7).to_i
        as_db   = (opts[:as_db] || 60.0).to_f
        return [] if samples.empty?

        q = firfilt_rrrf_create_dc_blocker(m, as_db)
        raise 'ERROR: firfilt_rrrf_create_dc_blocker failed' if q.null?

        begin
          n = samples.length
          in_ptr = float_ptr(samples)
          out_ptr = PubFFI::MemoryPointer.new(:float, n)
          rc = firfilt_rrrf_execute_block(q, in_ptr, n, out_ptr)
          raise "ERROR: firfilt_rrrf_execute_block rc=#{rc}" unless rc.zero?

          out_ptr.read_array_of_float(n)
        ensure
          firfilt_rrrf_destroy(q)
        end
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.available?                              # => true/false
          #{self}.freq_demod(iq:, kf: 0.5)                # FM I/Q → audio
          #{self}.resample(samples:, rate:, as_db: 60.0)  # arbitrary rate
          #{self}.fir_kaiser(samples:, length: 51, fc: 0.1, as_db: 60.0)
          #{self}.dc_block(samples:, m: 7, as_db: 60.0)

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
      end
    end
  end
end
