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

        # ── msresamp_crcf (complex arbitrary resampler) ───────────────
        attach_function :msresamp_crcf_create, %i[float float], :pointer
        attach_function :msresamp_crcf_destroy, [:pointer], :int
        attach_function :msresamp_crcf_execute,
                        %i[pointer pointer uint pointer pointer],
                        :int

        # ── nco_crcf (numerically-controlled oscillator / mixer) ──────
        LIQUID_NCO = 0
        LIQUID_VCO = 1
        attach_function :nco_crcf_create, [:int], :pointer
        attach_function :nco_crcf_destroy, [:pointer], :int
        attach_function :nco_crcf_set_frequency, %i[pointer float], :int
        attach_function :nco_crcf_mix_block_down,
                        %i[pointer pointer pointer uint],
                        :int

        # ── gmskdem (GMSK demodulator: k samp/sym → bit) ──────────────
        attach_function :gmskdem_create, %i[uint uint float], :pointer
        attach_function :gmskdem_destroy, [:pointer], :int
        attach_function :gmskdem_reset, [:pointer], :int
        attach_function :gmskdem_demodulate,
                        %i[pointer pointer pointer],
                        :int

        # ── fskdem (M-FSK demodulator: k samp/sym → symbol) ───────────
        attach_function :fskdem_create, %i[uint uint float uint], :pointer
        attach_function :fskdem_destroy, [:pointer], :int
        attach_function :fskdem_demodulate, %i[pointer pointer], :uint
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

      # Supported Method Parameters::
      # out = PWN::FFI::Liquid.resample_iq(
      #   iq:    'required - interleaved I/Q Array<Float>',
      #   rate:  'required - output/input ratio (>0)',
      #   as_db: 'optional - stop-band attenuation dB (default 60.0)'
      # )
      # Returns interleaved Array<Float> [I0,Q0,…] resampled by `rate`.

      public_class_method def self.resample_iq(opts = {})
        raise 'ERROR: libliquid not available' unless available?

        iq    = opts[:iq]
        rate  = opts[:rate].to_f
        as_db = (opts[:as_db] || 60.0).to_f
        n     = iq.length / 2
        raise 'ERROR: rate must be > 0' unless rate.positive?
        return iq.dup if n.zero?

        q = msresamp_crcf_create(rate, as_db)
        raise 'ERROR: msresamp_crcf_create failed' if q.null?

        begin
          ny_max = [1, (2 + (2 * rate * n)).ceil].max
          in_ptr = float_ptr(iq.first(n * 2))
          out_ptr = PubFFI::MemoryPointer.new(:float, ny_max * 2)
          ny_ptr  = PubFFI::MemoryPointer.new(:uint, 1)
          rc = msresamp_crcf_execute(q, in_ptr, n, out_ptr, ny_ptr)
          raise "ERROR: msresamp_crcf_execute rc=#{rc}" unless rc.zero?

          ny = ny_ptr.read_uint
          out_ptr.read_array_of_float(ny * 2)
        ensure
          msresamp_crcf_destroy(q)
        end
      end

      # Supported Method Parameters::
      # out = PWN::FFI::Liquid.mix_down(
      #   iq:   'required - interleaved I/Q Array<Float>',
      #   freq: 'required - normalised angular freq (rad/sample, i.e. 2π·f/fs)'
      # )
      # Returns interleaved Array<Float> shifted down by `freq`.

      public_class_method def self.mix_down(opts = {})
        raise 'ERROR: libliquid not available' unless available?

        iq   = opts[:iq]
        freq = opts[:freq].to_f
        n    = iq.length / 2
        return [] if n.zero?

        q = nco_crcf_create(LIQUID_NCO)
        raise 'ERROR: nco_crcf_create failed' if q.null?

        begin
          nco_crcf_set_frequency(q, freq)
          in_ptr  = float_ptr(iq.first(n * 2))
          out_ptr = PubFFI::MemoryPointer.new(:float, n * 2)
          rc = nco_crcf_mix_block_down(q, in_ptr, out_ptr, n)
          raise "ERROR: nco_crcf_mix_block_down rc=#{rc}" unless rc.zero?

          out_ptr.read_array_of_float(n * 2)
        ensure
          nco_crcf_destroy(q)
        end
      end

      # Supported Method Parameters::
      # bits = PWN::FFI::Liquid.gmsk_demod(
      #   iq:  'required - interleaved I/Q Array<Float>, length = k·sym·2',
      #   sps: 'required - samples per symbol (integer ≥ 2)',
      #   m:   'optional - filter delay (default 3)',
      #   bt:  'optional - Gaussian BT (default 0.35)'
      # )
      # Returns Array<0|1> (one bit per symbol, floor(n/sps) bits).

      public_class_method def self.gmsk_demod(opts = {})
        raise 'ERROR: libliquid not available' unless available?

        iq  = opts[:iq]
        k   = opts[:sps].to_i
        m   = (opts[:m] || 3).to_i
        bt  = (opts[:bt] || 0.35).to_f
        raise 'ERROR: sps must be ≥ 2' if k < 2

        n = iq.length / 2
        nsym = n / k
        return [] if nsym.zero?

        q = gmskdem_create(k, m, bt)
        raise 'ERROR: gmskdem_create failed' if q.null?

        begin
          in_ptr  = float_ptr(iq.first(nsym * k * 2))
          bit_ptr = PubFFI::MemoryPointer.new(:uint, 1)
          bits = Array.new(nsym)
          i = 0
          while i < nsym
            gmskdem_demodulate(q, in_ptr + (i * k * 2 * 4), bit_ptr)
            bits[i] = bit_ptr.read_uint & 1
            i += 1
          end
          bits
        ensure
          gmskdem_destroy(q)
        end
      end

      # Supported Method Parameters::
      # syms = PWN::FFI::Liquid.mfsk_demod(
      #   iq:  'required - interleaved I/Q Array<Float>',
      #   m:   'required - bits per symbol (1=2FSK, 2=4FSK, …)',
      #   sps: 'required - samples per symbol (integer ≥ 2^m)',
      #   bw:  'optional - normalised bandwidth 0..0.5 (default 0.25)'
      # )
      # Returns Array<Integer> of demodulated symbols (0..2^m-1).

      public_class_method def self.mfsk_demod(opts = {})
        raise 'ERROR: libliquid not available' unless available?

        iq  = opts[:iq]
        mb  = opts[:m].to_i
        k   = opts[:sps].to_i
        bw  = (opts[:bw] || 0.25).to_f
        n   = iq.length / 2
        nsym = n / k
        return [] if nsym.zero?

        q = fskdem_create(mb, k, bw, 0)
        raise 'ERROR: fskdem_create failed' if q.null?

        begin
          in_ptr = float_ptr(iq.first(nsym * k * 2))
          syms = Array.new(nsym)
          i = 0
          while i < nsym
            syms[i] = fskdem_demodulate(q, in_ptr + (i * k * 2 * 4))
            i += 1
          end
          syms
        ensure
          fskdem_destroy(q)
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
#{self}.resample_iq(iq:, rate:, as_db: 60.0)     # complex resample
#{self}.mix_down(iq:, freq:)                     # NCO mix (rad/samp)
#{self}.gmsk_demod(iq:, sps:, m: 3, bt: 0.35)    # I/Q → bits
#{self}.mfsk_demod(iq:, m:, sps:, bw: 0.25)      # I/Q → symbols

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
