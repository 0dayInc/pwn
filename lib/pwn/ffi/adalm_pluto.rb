# frozen_string_literal: true

require 'ffi'

PubFFI = ::FFI unless defined?(PubFFI) # rubocop:disable Style/RedundantConstantBase

module PWN
  module FFI
    # Thin libiio binding specialised for the ADALM-PLUTO (AD9363).
    #
    # Control-plane + blocking RX of interleaved CS16 I/Q so
    # PWN::SDR::Decoder::* can pull MHz-rate complex samples without
    # GQRX's 48 kHz audio tap and without shelling out to iio_*.
    # libad9361 is used only for optional bb_rate helpers when present.
    #
    # If libiio is missing `.available?` is false and callers fall back
    # to RTLSdr / HackRF / SoapySDR / pure-Ruby detector paths.
    #
    # Default URI tries USB (local) first: "ip:192.168.2.1" is the stock
    # Ethernet/USB-gadget address of an unconfigured Pluto.
    module AdalmPluto
      extend PubFFI::Library

      @load_error = nil
      begin
        ffi_lib %w[iio libiio.so.0 libiio.so]
      rescue LoadError => e
        @load_error = e
      end

      class << self
        attr_reader :load_error
      end

      # Optional libad9361 (bb rate convenience). Soft-fail.
      @ad9361_load_error = nil
      # Optional soft binding to libad9361 (bb_rate helper only).
      module Ad9361
        extend PubFFI::Library

        @load_error = nil
        begin
          ffi_lib %w[ad9361 libad9361.so.0 libad9361.so]
        rescue LoadError => e
          @load_error = e
        end
        class << self
          attr_reader :load_error
        end
        attach_function :ad9361_set_bb_rate, %i[pointer ulong], :int unless @load_error
      end

      unless @load_error
        # ── library / strerror ─────────────────────────────────────────
        attach_function :iio_library_get_version,
                        %i[pointer pointer pointer],
                        :void
        attach_function :iio_strerror, %i[int pointer size_t], :void

        # ── scan / enumerate ───────────────────────────────────────────
        attach_function :iio_create_scan_context, %i[string int], :pointer
        attach_function :iio_scan_context_destroy, [:pointer], :void
        attach_function :iio_scan_context_get_info_list,
                        %i[pointer pointer],
                        :ssize_t
        attach_function :iio_context_info_list_free, [:pointer], :void
        attach_function :iio_context_info_get_description, [:pointer], :string
        attach_function :iio_context_info_get_uri, [:pointer], :string

        # ── context ────────────────────────────────────────────────────
        attach_function :iio_create_default_context, [], :pointer
        attach_function :iio_create_context_from_uri, [:string], :pointer
        attach_function :iio_create_network_context, [:string], :pointer
        attach_function :iio_context_destroy, [:pointer], :void
        attach_function :iio_context_get_name, [:pointer], :string
        attach_function :iio_context_get_description, [:pointer], :string
        attach_function :iio_context_get_devices_count, [:pointer], :uint
        attach_function :iio_context_get_device, %i[pointer uint], :pointer
        attach_function :iio_context_find_device, %i[pointer string], :pointer
        attach_function :iio_context_set_timeout, %i[pointer uint], :int

        # ── device ─────────────────────────────────────────────────────
        attach_function :iio_device_get_id, [:pointer], :string
        attach_function :iio_device_get_name, [:pointer], :string
        attach_function :iio_device_get_channels_count, [:pointer], :uint
        attach_function :iio_device_get_channel, %i[pointer uint], :pointer
        attach_function :iio_device_find_channel,
                        %i[pointer string bool],
                        :pointer
        attach_function :iio_device_attr_write,
                        %i[pointer string string],
                        :ssize_t
        attach_function :iio_device_attr_write_longlong,
                        %i[pointer string long_long],
                        :int
        attach_function :iio_device_attr_read,
                        %i[pointer string pointer size_t],
                        :ssize_t
        attach_function :iio_device_attr_read_longlong,
                        %i[pointer string pointer],
                        :int
        attach_function :iio_device_create_buffer,
                        %i[pointer size_t bool],
                        :pointer

        # ── channel ────────────────────────────────────────────────────
        attach_function :iio_channel_get_id, [:pointer], :string
        attach_function :iio_channel_get_name, [:pointer], :string
        attach_function :iio_channel_is_output, [:pointer], :bool
        attach_function :iio_channel_is_scan_element, [:pointer], :bool
        attach_function :iio_channel_enable, [:pointer], :void
        attach_function :iio_channel_disable, [:pointer], :void
        attach_function :iio_channel_attr_write,
                        %i[pointer string string],
                        :ssize_t
        attach_function :iio_channel_attr_write_longlong,
                        %i[pointer string long_long],
                        :int
        attach_function :iio_channel_attr_read_longlong,
                        %i[pointer string pointer],
                        :int

        # ── buffer ─────────────────────────────────────────────────────
        attach_function :iio_buffer_destroy, [:pointer], :void
        attach_function :iio_buffer_refill, [:pointer], :ssize_t
        attach_function :iio_buffer_start, [:pointer], :pointer
        attach_function :iio_buffer_end, [:pointer], :pointer
        attach_function :iio_buffer_step, [:pointer], :ptrdiff_t
        attach_function :iio_buffer_first, %i[pointer pointer], :pointer
        attach_function :iio_buffer_set_blocking_mode, %i[pointer bool], :int
        attach_function :iio_buffer_cancel, [:pointer], :void
      end

      DEFAULT_URI = 'ip:192.168.2.1'
      PHY_NAME    = 'ad9361-phy'
      RX_NAME     = 'cf-ad9361-lpc'
      # Stock Pluto RX LO channel
      RX_LO_NAME  = 'altvoltage0'

      # Supported Method Parameters::
      # PWN::FFI::AdalmPluto.available?

      public_class_method def self.available?
        !@load_error && respond_to?(:iio_create_default_context, true)
      rescue StandardError
        false
      end

      # Supported Method Parameters::
      # info = PWN::FFI::AdalmPluto.info
      # Returns { available:, major:, minor:, git_tag:, ad9361: }

      public_class_method def self.info
        return { available: false, error: @load_error&.message } unless available?

        maj = PubFFI::MemoryPointer.new(:uint)
        min = PubFFI::MemoryPointer.new(:uint)
        # git_tag is a caller-owned char[8] buffer (NOT char**).
        git = PubFFI::MemoryPointer.new(:char, 8)
        git.put_bytes(0, "\0" * 8)
        iio_library_get_version(maj, min, git)
        tag = git.read_string
        {
          available: true,
          major: maj.read_uint,
          minor: min.read_uint,
          git_tag: tag,
          ad9361: Ad9361.load_error.nil? && Ad9361.respond_to?(:ad9361_set_bb_rate, true)
        }
      end

      # Supported Method Parameters::
      # uris = PWN::FFI::AdalmPluto.list_uris(backends: 'usb,ip,local')
      # Returns Array<Hash> of { uri:, description: }

      public_class_method def self.list_uris(opts = {})
        raise 'ERROR: libiio not available' unless available?

        backends = (opts[:backends] || 'usb,ip,local').to_s
        scan = iio_create_scan_context(backends, 0)
        return [] if scan.null?

        info_ptr = PubFFI::MemoryPointer.new(:pointer)
        info_ptr.write_pointer(PubFFI::Pointer::NULL)
        begin
          n = iio_scan_context_get_info_list(scan, info_ptr)
          return [] if n <= 0

          base = info_ptr.read_pointer
          return [] if base.null?

          Array.new(n) do |i|
            entry = base.get_pointer(i * PubFFI::Pointer.size)
            next { uri: '', description: '' } if entry.null?

            {
              uri: iio_context_info_get_uri(entry).to_s,
              description: iio_context_info_get_description(entry).to_s
            }
          end
        ensure
          base = info_ptr.read_pointer
          iio_context_info_list_free(base) if base && !base.null?
          iio_scan_context_destroy(scan)
        end
      rescue StandardError
        []
      end

      # Supported Method Parameters::
      # ctx = PWN::FFI::AdalmPluto.open(uri: 'ip:192.168.2.1')
      # Returns opaque iio_context* pointer. ALWAYS pair with .close.

      public_class_method def self.open(opts = {})
        raise 'ERROR: libiio not available' unless available?

        uri = opts[:uri]
        ctx =
          if uri.to_s.empty?
            # try default USB/local first, then stock IP
            c = iio_create_default_context
            (c.null? ? iio_create_context_from_uri(DEFAULT_URI) : c)
          else
            iio_create_context_from_uri(uri.to_s)
          end
        raise "ERROR: iio_create_context failed for #{uri.inspect}" if ctx.null?

        iio_context_set_timeout(ctx, (opts[:timeout_ms] || 5_000).to_i)
        ctx
      end

      # Supported Method Parameters::
      # PWN::FFI::AdalmPluto.close(context: pointer)

      public_class_method def self.close(opts = {})
        ctx = opts[:context]
        return unless ctx && !ctx.null?

        iio_context_destroy(ctx)
        nil
      end

      # Supported Method Parameters::
      # meta = PWN::FFI::AdalmPluto.device_info(context: pointer)
      # Returns { name:, description:, devices: [{id:, name:}, ...] }

      public_class_method def self.device_info(opts = {})
        ctx = opts[:context]
        raise 'ERROR: :context required' if ctx.nil? || ctx.null?

        n = iio_context_get_devices_count(ctx)
        devices = Array.new(n) do |i|
          d = iio_context_get_device(ctx, i)
          {
            id: iio_device_get_id(d).to_s,
            name: (iio_device_get_name(d) || '').to_s
          }
        end
        {
          name: iio_context_get_name(ctx).to_s,
          description: iio_context_get_description(ctx).to_s,
          devices: devices
        }
      end

      # Supported Method Parameters::
      # PWN::FFI::AdalmPluto.configure(
      #   context:  'required - pointer from .open',
      #   freq_hz:  'required - RX LO frequency Hz',
      #   rate_hz:  'optional - sample rate (default 2_500_000)',
      #   bw_hz:    'optional - RF bandwidth (default = rate_hz)',
      #   gain_db:  'optional - manual gain dB; nil = slow_attack AGC',
      #   gain_mode:'optional - slow_attack|fast_attack|manual|hybrid'
      # )

      public_class_method def self.configure(opts = {}) # rubocop:disable Naming/PredicateMethod
        ctx = opts[:context]
        raise 'ERROR: :context required' if ctx.nil? || ctx.null?

        freq = opts[:freq_hz].to_i
        rate = (opts[:rate_hz] || 2_500_000).to_i
        bw   = (opts[:bw_hz] || rate).to_i
        raise 'ERROR: :freq_hz required' if freq <= 0

        phy = iio_context_find_device(ctx, PHY_NAME)
        raise "ERROR: phy device #{PHY_NAME.inspect} not found" if phy.null?

        # RX LO
        lo = iio_device_find_channel(phy, RX_LO_NAME, true) # output channel
        if lo.null?
          # some firmwares expose "RX_LO"
          lo = iio_device_find_channel(phy, 'RX_LO', true)
        end
        raise 'ERROR: RX LO channel not found' if lo.null?

        check_ssize!(iio_channel_attr_write_longlong(lo, 'frequency', freq), 'RX LO frequency')

        # Sampling frequency + RF bandwidth on voltage0 (RX)
        rx_chn = iio_device_find_channel(phy, 'voltage0', false)
        raise 'ERROR: phy voltage0 (RX) not found' if rx_chn.null?

        check_ssize!(iio_channel_attr_write_longlong(rx_chn, 'sampling_frequency', rate), 'sampling_frequency')
        check_ssize!(iio_channel_attr_write_longlong(rx_chn, 'rf_bandwidth', bw), 'rf_bandwidth')

        gain_mode = opts[:gain_mode]
        if opts.key?(:gain_db) && !opts[:gain_db].nil?
          gain_mode ||= 'manual'
          check_ssize!(iio_channel_attr_write(rx_chn, 'gain_control_mode', gain_mode), 'gain_control_mode')
          check_ssize!(iio_channel_attr_write_longlong(rx_chn, 'hardwaregain', opts[:gain_db].to_i), 'hardwaregain')
        else
          gain_mode ||= 'slow_attack'
          check_ssize!(iio_channel_attr_write(rx_chn, 'gain_control_mode', gain_mode), 'gain_control_mode')
        end

        # Prefer libad9361 bb_rate when linked (programs FIR + HB chain)
        if Ad9361.load_error.nil? && Ad9361.respond_to?(:ad9361_set_bb_rate, true)
          begin
            Ad9361.ad9361_set_bb_rate(phy, rate)
          rescue StandardError
            nil
          end
        end

        true
      end

      # Supported Method Parameters::
      # handle = PWN::FFI::AdalmPluto.start_rx(
      #   context:     'required - pointer from .open',
      #   samples:     'optional - samples-per-refill (default 262144)',
      #   cyclic:      'optional - cyclic buffer (default false)'
      # )
      # Returns { buffer:, rx:, i_chn:, q_chn:, samples: } — pair with .stop_rx.

      public_class_method def self.start_rx(opts = {})
        ctx = opts[:context]
        raise 'ERROR: :context required' if ctx.nil? || ctx.null?

        nsamps = (opts[:samples] || 262_144).to_i
        rx = iio_context_find_device(ctx, RX_NAME)
        raise "ERROR: RX streaming device #{RX_NAME.inspect} not found" if rx.null?

        # Enable voltage0 (I) + voltage1 (Q) scan elements
        i_chn = iio_device_find_channel(rx, 'voltage0', false)
        q_chn = iio_device_find_channel(rx, 'voltage1', false)
        raise 'ERROR: RX I/Q channels not found' if i_chn.null? || q_chn.null?

        iio_channel_enable(i_chn)
        iio_channel_enable(q_chn)

        buf = iio_device_create_buffer(rx, nsamps, opts[:cyclic] ? true : false)
        raise 'ERROR: iio_device_create_buffer failed' if buf.null?

        iio_buffer_set_blocking_mode(buf, true)
        { buffer: buf, rx: rx, i_chn: i_chn, q_chn: q_chn, samples: nsamps }
      end

      # Supported Method Parameters::
      # iq_cs16 = PWN::FFI::AdalmPluto.read_sync(handle: hash_from_start_rx)
      # Returns binary String of interleaved little-endian signed-16 I/Q
      # (I0,Q0,I1,Q1,…) — same contract as a cs16 capture file.

      public_class_method def self.read_sync(opts = {})
        h = opts[:handle]
        raise 'ERROR: :handle required' unless h.is_a?(Hash)

        buf = h[:buffer]
        raise 'ERROR: handle missing :buffer' if buf.nil? || buf.null?

        nbytes = iio_buffer_refill(buf)
        raise "ERROR: iio_buffer_refill rc=#{nbytes}" if nbytes.negative?

        start = iio_buffer_start(buf)
        # Pluto packs I then Q as sequential int16 scan elements; step covers both.
        start.read_string(nbytes)
      end

      # Supported Method Parameters::
      # PWN::FFI::AdalmPluto.stop_rx(handle: hash_from_start_rx)

      public_class_method def self.stop_rx(opts = {})
        h = opts[:handle]
        return unless h.is_a?(Hash)

        buf = h[:buffer]
        if buf && !buf.null?
          begin
            iio_buffer_cancel(buf)
          rescue StandardError
            nil
          end
          iio_buffer_destroy(buf)
        end
        nil
      end

      # High-level one-shot: open → configure → start_rx → N refills → stop → close.
      # Supported Method Parameters::
      # iq = PWN::FFI::AdalmPluto.capture(
      #   freq_hz: 'required',
      #   rate_hz: 2_500_000,
      #   bytes:   1_048_576,   # approximate payload size
      #   uri:     nil,
      #   gain_db: nil
      # )
      # Returns { iq_cs16: String, rate_hz:, freq_hz:, samples: }

      public_class_method def self.capture(opts = {})
        raise 'ERROR: :freq_hz required' unless opts[:freq_hz]

        rate  = (opts[:rate_hz] || 2_500_000).to_i
        want  = (opts[:bytes] || 1_048_576).to_i
        ctx   = self.open(uri: opts[:uri], timeout_ms: opts[:timeout_ms])
        handle = nil
        begin
          configure(
            context: ctx,
            freq_hz: opts[:freq_hz],
            rate_hz: rate,
            bw_hz: opts[:bw_hz],
            gain_db: opts[:gain_db],
            gain_mode: opts[:gain_mode]
          )
          # each sample = 4 bytes (I s16 + Q s16)
          nsamps = (want / 4).clamp(4_096, 1_048_576)
          handle = start_rx(context: ctx, samples: nsamps)
          chunks = []
          got = 0
          while got < want
            chunk = read_sync(handle: handle)
            break if chunk.bytesize.zero?

            chunks << chunk
            got += chunk.bytesize
          end
          {
            iq_cs16: chunks.join,
            rate_hz: rate,
            freq_hz: opts[:freq_hz].to_i,
            samples: got / 4
          }
        ensure
          stop_rx(handle: handle) if handle
          close(context: ctx)
        end
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
          #{self}.list_uris
          ctx = #{self}.open(uri: 'ip:192.168.2.1')   # or nil for default
          #{self}.device_info(context: ctx)
          #{self}.configure(context: ctx, freq_hz:, rate_hz: 2_500_000, gain_db: nil)
          h = #{self}.start_rx(context: ctx, samples: 262_144)
          iq = #{self}.read_sync(handle: h)            # cs16le interleaved String
          #{self}.stop_rx(handle: h)
          #{self}.close(context: ctx)

          # one-shot
          cap = #{self}.capture(freq_hz: 1090e6, rate_hz: 2_500_000, bytes: 1_048_576)

          #{self}.authors
        "
      end

      class << self
        private

        def check_ssize!(rc, what) # rubocop:disable Naming/MethodParameterName
          return if rc.is_a?(Integer) && rc >= 0

          msg = strerror((-rc).to_i)
          raise "ERROR: AdalmPluto #{what} rc=#{rc} (#{msg})"
        end

        def strerror(err)
          return err.to_s unless available?

          buf = PubFFI::MemoryPointer.new(:char, 256)
          iio_strerror(err, buf, 256)
          buf.read_string
        rescue StandardError
          err.to_s
        end
      end
    end
  end
end
