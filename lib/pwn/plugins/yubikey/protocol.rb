# frozen_string_literal: true

module PWN
  module Plugins
    module YubiKey
      # Native binary codecs shared by YubiKey application protocols.
      module Protocol
        MAX_BYTES = 1_048_576

        public_class_method def self.require_confirm(opts = {})
          raise ConfirmationRequired, 'This device operation requires confirm: true' unless opts[:confirm] == true

          :confirmed
        end

        public_class_method def self.secret(opts = {})
          name = opts[:name]
          raise ArgumentError, 'A nonsecret field name Symbol is required' unless name.is_a?(Symbol)

          value = opts[:value]
          provider = opts[:secret_provider]
          value = provider.call(name) if value.nil? && provider.respond_to?(:call)
          raise ArgumentError, "An explicit #{name} String is required" unless value.is_a?(String) && !value.empty? && value.bytesize <= MAX_BYTES

          value.b
        end

        public_class_method def self.version_at_least?(opts = {})
          version = opts[:version]
          minimum = opts[:minimum]
          raise ArgumentError, 'Firmware versions must be three integer bytes' unless [version, minimum].all? { |tuple| tuple.is_a?(Array) && tuple.length == 3 && tuple.all? { |part| part.is_a?(Integer) && part.between?(0, 255) } }

          (version <=> minimum) >= 0
        end

        public_class_method def self.parse_args(opts = {})
          args = opts[:args]
          raise ArgumentError, 'args must be a bounded Array of exact text arguments' unless args.is_a?(Array) && args.length <= 256 && args.all? { |item| item.is_a?(String) && item.valid_encoding? && !item.b.match?(/[\x00-\x1f\x7f]/) } && args.sum(&:bytesize) <= 65_536

          flags = opts.fetch(:flags, [])
          values = opts.fetch(:values, [])
          remaining = args.dup
          options = {}
          positionals = []
          literal = false
          until remaining.empty?
            item = remaining.shift
            if literal || !item.start_with?('-') || item == '-'
              positionals << item
            elsif item == '--'
              literal = true
            elsif flags.include?(item)
              options[item.delete_prefix('--').tr('-', '_').to_sym] = true
            elsif values.include?(item)
              raise ArgumentError, 'Missing option value' if remaining.empty? || remaining.first.start_with?('--')

              key = item.delete_prefix('--').tr('-', '_').to_sym
              value = remaining.shift
              options[key] = options.key?(key) ? [*options[key], value] : value
            else
              raise ArgumentError, 'Unsupported native option; credentials belong in memory, not command arguments'
            end
          end
          { positionals: positionals, options: options }
        end

        # Carries only the status word, never credential-bearing command data.
        class APDUError < ResponseError
          attr_reader :status

          def initialize(opts = {})
            @status = opts.fetch(:status)
            super(format('YubiKey APDU failed (status %04x)', @status))
          end
        end

        public_class_method def self.select(opts = {})
          aid = opts[:aid]
          raise ArgumentError, 'Application AID must contain 1 to 32 bytes' unless aid.is_a?(String) && aid.bytesize.between?(1, 32)

          apdu(opts.except(:aid).merge(ins: 0xa4, p1: 4, data: aid))
        end

        public_class_method def self.apdu(opts = {})
          connection = opts[:connection]
          raise ArgumentError, 'A native connection with exchange is required' unless connection.respond_to?(:exchange)

          timeout = opts.fetch(:timeout, 30)
          maximum = opts.fetch(:max_response, MAX_BYTES)
          raise ArgumentError, 'APDU timeout must be finite positive seconds' unless (timeout.is_a?(Integer) || timeout.is_a?(Float)) && timeout.finite? && timeout.positive?
          raise ArgumentError, 'APDU response limit must be a positive bounded integer' unless maximum.is_a?(Integer) && maximum.between?(1, MAX_BYTES)

          command_data = opts.fetch(:data, ''.b)
          descriptor = connection.respond_to?(:descriptor) ? connection.descriptor : nil
          forced = descriptor.is_a?(Hash) && descriptor[:extended_apdu] == true
          raise ArgumentError, 'Secure channels require extended APDU framing' if forced && opts[:extended] == false

          extended = forced ? true : opts.fetch(:extended, false)
          raise ArgumentError, 'APDU data must be a String bounded to 65535 bytes' unless command_data.is_a?(String) && command_data.bytesize <= 65_535
          raise ArgumentError, 'extended must be a Boolean' unless [true, false].include?(extended)

          continuation = { cla: opts.fetch(:cla, 0), ins: opts.fetch(:get_response_ins, 0xc0), le: opts[:get_response_le] }
          command_frame(continuation)
          frames = []
          offset = 0
          unless extended
            while command_data.bytesize - offset > 255
              frames << opts.merge(cla: opts.fetch(:cla, 0) | 0x10, data: command_data.byteslice(offset, 255), le: nil, extended: false)
              offset += 255
            end
          end
          frames << opts.merge(data: command_data.byteslice(offset..), extended: extended)
          frames = frames.map { |command| { command: command, frame: command_frame(command) } }
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          context = { connection: connection, deadline: deadline, maximum: maximum, continuation: continuation }
          frames[0...-1].each do |frame|
            response = exchange_frame(context.merge(frame))
            raise ResponseError, 'Unexpected data in command-chaining acknowledgement' unless response.empty?
          end
          exchange_frame(context.merge(frames.last))
        end

        private_class_method def self.exchange_frame(opts = {})
          connection = opts[:connection]
          frame = opts[:frame]
          command = opts[:command]
          maximum = opts[:maximum]
          data = ''.b
          corrected = false
          256.times do
            remaining = opts[:deadline] - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            raise TimeoutError, 'YubiKey APDU timed out; command state may be uncertain' unless remaining.positive?

            response = connection.exchange(protocol: :apdu, data: frame, timeout: remaining)
            raise ResponseError, 'Invalid or oversized APDU response' unless response.is_a?(String) && response.bytesize.between?(2, maximum + 2)

            status = response.byteslice(-2, 2).unpack1('n')
            if (status & 0xff00) == 0x6c00 && !corrected
              length = status & 0xff
              command = command.merge(le: length.zero? ? 256 : length)
              frame = command_frame(command)
              corrected = true
              next
            end
            raise APDUError.new(status: status) unless status == 0x9000 || (status & 0xff00) == 0x6100

            data << response.b.byteslice(0, response.bytesize - 2)
            raise ResponseError, 'APDU response limit exceeded' if data.bytesize > maximum
            return data if status == 0x9000

            continuation = opts[:continuation]
            command = continuation.merge(cla: continuation[:cla] & ~0x10, le: continuation[:le].nil? ? status & 0xff : continuation[:le])
            frame = command_frame(command)
          end
          raise ResponseError, 'Too many APDU response fragments'
        end

        private_class_method def self.command_frame(opts = {})
          header = [opts.fetch(:cla, 0), opts[:ins], opts.fetch(:p1, 0), opts.fetch(:p2, 0)]
          raise ArgumentError, 'APDU header fields must be integer bytes' unless header.all? { |byte| byte.is_a?(Integer) && byte.between?(0, 255) }

          data = opts.fetch(:data, ''.b)
          le = opts[:le]
          extended = opts.fetch(:extended, false)
          maximum = extended ? 65_535 : 255
          raise ArgumentError, 'APDU data exceeds frame capacity' unless data.is_a?(String) && data.bytesize <= maximum
          raise ArgumentError, 'APDU Le is outside the selected frame capacity' unless le.nil? || (le.is_a?(Integer) && le.between?(0, maximum + 1))

          frame = header.pack('C*')
          if extended
            frame << "\x00".b << [data.bytesize].pack('n') << data.b unless data.empty?
            unless le.nil?
              frame << "\x00".b if data.empty?
              frame << [le & 0xffff].pack('n')
            end
          else
            frame << [data.bytesize].pack('C') << data.b unless data.empty?
            frame << [le & 0xff].pack('C') unless le.nil?
            frame << "\x00".b if data.empty? && le.nil?
          end
          frame
        end

        public_class_method def self.tlv(opts = {})
          tag = opts[:tag]
          value = opts[:value]
          raise ArgumentError, 'TLV tag must be a positive integer' unless tag.is_a?(Integer) && tag.positive? && tag <= 0xffffffffff
          raise ArgumentError, 'TLV value must be a bounded String' unless value.is_a?(String) && value.bytesize <= MAX_BYTES

          hex = tag.to_s(16)
          hex = "0#{hex}" if hex.length.odd?
          tag_bytes = [hex].pack('H*')
          parsed, finish = read_tag(data: tag_bytes, offset: 0)
          raise ArgumentError, 'Invalid BER tag' unless parsed == tag && finish == tag_bytes.bytesize

          length = value.bytesize
          if length < 128
            length_bytes = [length].pack('C')
          else
            hex = length.to_s(16)
            hex = "0#{hex}" if hex.length.odd?
            encoded = [hex].pack('H*')
            length_bytes = [0x80 | encoded.bytesize].pack('C') + encoded
          end
          raise ArgumentError, 'TLV frame exceeds one MiB' if tag_bytes.bytesize + length_bytes.bytesize + value.bytesize > MAX_BYTES

          tag_bytes + length_bytes + value.b
        rescue ResponseError
          raise ArgumentError, 'Invalid BER tag', cause: nil
        end

        public_class_method def self.untlv(opts = {})
          data = opts[:data]
          raise ArgumentError, 'TLV data must be a bounded String' unless data.is_a?(String) && data.bytesize <= MAX_BYTES

          data = data.b
          rows = []
          offset = 0
          while offset < data.bytesize
            tag, offset = read_tag(data: data, offset: offset)
            length = data.getbyte(offset)
            raise ResponseError, 'Truncated TLV length' unless length

            offset += 1
            if length >= 128
              count = length & 0x7f
              raise ResponseError, 'Invalid or truncated TLV length' unless count.between?(1, 4) && offset + count <= data.bytesize

              length = data.byteslice(offset, count).bytes.reduce(0) { |total, byte| (total << 8) | byte }
              offset += count
            end
            raise ResponseError, 'Truncated or oversized TLV value' if length > MAX_BYTES || offset + length > data.bytesize

            rows << { tag: tag, value: data.byteslice(offset, length) }
            offset += length
          end
          rows
        end

        public_class_method def self.tlv_map(opts = {})
          untlv(data: opts[:data]).each_with_object({}) do |row, result|
            raise ResponseError, 'Duplicate TLV tag in unique-field response' if result.key?(row[:tag])

            result[row[:tag]] = row[:value]
          end
        end

        private_class_method def self.read_tag(opts = {})
          data = opts[:data]
          offset = opts[:offset]
          first = data.getbyte(offset)
          raise ResponseError, 'Invalid or truncated BER tag' unless first && first.positive?

          tag = first
          offset += 1
          if first.allbits?(0x1f)
            count = 1
            loop do
              byte = data.getbyte(offset)
              raise ResponseError, 'Invalid or truncated BER tag' unless byte && count < 5

              tag = (tag << 8) | byte
              offset += 1
              count += 1
              break if byte.nobits?(0x80)
            end
          end
          [tag, offset]
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts <<~HELP
            USAGE:
            # Require explicit caller consent before device mutations or authentication.
            #{self}.require_confirm(
              confirm: 'required - literal true authorizing the selected operation'
            )
            # Obtain a secret in memory without implicit prompting or fallback.
            #{self}.secret(
              name: 'required - nonsecret field-name Symbol identifying the credential',
              value: 'optional - explicit nonempty raw secret String',
              secret_provider: 'optional - caller callback receiving the field Symbol when value is nil'
            )
            # Compare explicit firmware tuples without repairing invalid inputs.
            #{self}.version_at_least?(
              version: 'required - observed firmware Array of three integer bytes',
              minimum: 'required - minimum firmware Array of three integer bytes'
            )
            # Parse declared native operation options without normalizing argument values.
            #{self}.parse_args(
              args: 'required - bounded Array of exact argument Strings',
              flags: 'optional - supported Boolean long options, defaults to empty',
              values: 'optional - supported value-taking long options, defaults to empty'
            )
            # Select a smartcard application by its binary AID.
            #{self}.select(
              connection: 'required - native exchange-capable connection',
              aid: 'required - raw application identifier, 1 to 32 bytes',
              timeout: 'optional - finite positive total seconds, defaults to 30'
            )
            # Exchange a smartcard command and assemble bounded response fragments.
            #{self}.apdu(
              connection: 'required - native exchange-capable connection',
              ins: 'required - integer instruction byte',
              cla: 'optional - integer class byte, defaults to zero',
              p1: 'optional - first integer parameter byte, defaults to zero',
              p2: 'optional - second integer parameter byte, defaults to zero',
              data: 'optional - raw command bytes, defaults to empty',
              le: 'optional - response-length integer; nil omits Le',
              extended: 'optional - true selects extended APDU framing; false chains short frames',
              get_response_ins: 'optional - continuation instruction byte, defaults to ISO GET RESPONSE (192)',
              get_response_le: 'optional - fixed short continuation Le; nil uses the card status length',
              timeout: 'optional - finite positive total seconds, defaults to 30',
              max_response: 'optional - bounded maximum response bytes, defaults to one MiB'
            )
            # Encode one BER-TLV record without interpreting its binary value.
            #{self}.tlv(
              tag: 'required - positive BER tag integer',
              value: 'required - raw String; the complete encoded frame is bounded to one MiB'
            )
            # Decode ordered BER-TLV records while retaining repeated tags.
            #{self}.untlv(
              data: 'required - raw BER-TLV String bounded to one MiB'
            )
            # Decode a unique-field response and reject duplicate TLV tags.
            #{self}.tlv_map(
              data: 'required - raw BER-TLV String with unique tags'
            )
            # Return module author information.
            #{self}.authors
          HELP
          nil
        end
      end
    end
  end
end
