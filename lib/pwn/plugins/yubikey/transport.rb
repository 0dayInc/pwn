# frozen_string_literal: true

# rubocop:disable Lint/RescueException -- Native resource ownership must survive Interrupt/SystemExit; errors are re-raised or forwarded, never logged.

require 'securerandom'
require 'English'

module PWN
  module Plugins
    module YubiKey
      # Native HIDAPI and PC/SC only. Requiring this file does not load a shared
      # library, initialize a library, enumerate devices or open a reader.
      module Transport
        # Each binding object owns its platform ABI. No PWN::FFI name resolution.
        class NativeLibrary
          attr_reader :library, :platform, :kind, :dword, :handle_type, :pci

          def initialize(kind, library: nil, platform: nil)
            require 'ffi'
            @kind = kind
            @users = 0
            @mutex = Mutex.new
            @platform = platform || (if ::FFI::Platform.windows?
                                       :windows
                                     else
                                       (::FFI::Platform.mac? ? :macos : :linux)
                                     end)
            @library = library || Module.new
            @library.extend(::FFI::Library)
            case kind
            when :hid then bind_hid
            when :pcsc then bind_pcsc
            else raise ArgumentError, 'backend must be :hid or :pcsc'
            end
          rescue LoadError, ::FFI::NotFoundError => e
            raise DependencyError, "Native #{kind} library unavailable; install HIDAPI for USB HID or PC/SC for smartcard/NFC (#{e.class})"
          end

          def acquire
            @mutex.synchronize do
              raise CommandError, 'HIDAPI initialization failed' if @users.zero? && library.hid_init.negative?

              @users += 1
            end
          end

          def release
            @mutex.synchronize do
              @users -= 1
              library.hid_exit if @users.zero?
            end
            :released
          end

          def devices
            kind == :hid ? HIDInventory.new(self).devices : PCSCInventory.new(self).devices
          end

          def open(descriptor)
            kind == :hid ? HIDIO.new(self, descriptor[:device_path]) : PCSCIO.new(self, descriptor[:reader])
          end

          private

          def bind_pcsc
            @dword = platform == :linux ? :ulong : :uint32
            result = platform == :linux ? :long : :int32
            @handle_type = platform == :windows ? :uintptr_t : result
            library.ffi_convention(:stdcall) if platform == :windows
            names = case platform
                    when :windows then ['winscard.dll']
                    when :macos then ['/System/Library/Frameworks/PCSC.framework/PCSC']
                    else ['libpcsclite.so.1', 'libpcsclite.so']
                    end
            library.ffi_lib(names)
            {
              SCardEstablishContext: [[dword, :pointer, :pointer, :pointer], result],
              SCardReleaseContext: [[handle_type], result], SCardCancel: [[handle_type], result],
              SCardDisconnect: [[handle_type, dword], result],
              SCardGetAttrib: [[handle_type, dword, :pointer, :pointer], result],
              SCardTransmit: [[handle_type, :pointer, :pointer, dword, :pointer, :pointer, :pointer], result]
            }.each { |name, (args, output)| library.attach_function(name, args, output, blocking: true) }
            { SCardListReaders: [handle_type, :pointer, :pointer, :pointer],
              SCardConnect: [handle_type, :pointer, dword, dword, :pointer, :pointer] }.each do |name, args|
              symbol = platform == :windows ? :"#{name}W" : name
              library.attach_function(name, symbol, args, result, blocking: true)
            end
            # Use exported PCI structs, not a guessed macOS struct packing.
            @pci = { 1 => 'g_rgSCardT0Pci', 2 => 'g_rgSCardT1Pci' }.transform_values do |symbol|
              pointer = library.ffi_libraries.filter_map { |lib| lib.find_symbol(symbol) }.first
              raise DependencyError, 'PC/SC library has no protocol control information symbols' unless pointer

              pointer
            end
          end

          def bind_hid
            names = case platform
                    when :windows then ['hidapi.dll']
                    when :macos then ['libhidapi.dylib', '/opt/homebrew/lib/libhidapi.dylib', '/usr/local/lib/libhidapi.dylib']
                    else ['libhidapi-hidraw.so.0', 'libhidapi-hidraw.so', 'libhidapi-libusb.so.0', 'libhidapi-libusb.so', 'libhidapi.so']
                    end
            library.ffi_lib(names)
            {
              hid_init: [[], :int], hid_exit: [[], :int],
              hid_enumerate: [%i[ushort ushort], :pointer], hid_free_enumeration: [[:pointer], :void],
              hid_open_path: [[:string], :pointer], hid_close: [[:pointer], :void],
              hid_write: [%i[pointer pointer size_t], :int],
              hid_read_timeout: [%i[pointer pointer size_t int], :int],
              hid_send_feature_report: [%i[pointer pointer size_t], :int],
              hid_get_feature_report: [%i[pointer pointer size_t], :int]
            }.each { |name, (args, result)| library.attach_function(name, args, result, blocking: true) }
          end
        end

        # C structures are created only after the lazy FFI dependency is loaded.
        class HIDInventory
          def initialize(native)
            @native = native
            @info = Class.new(::FFI::Struct) do
              layout :path, :pointer, :vendor_id, :ushort, :product_id, :ushort,
                     :serial_number, :pointer, :release_number, :ushort,
                     :manufacturer_string, :pointer, :product_string, :pointer,
                     :usage_page, :ushort, :usage, :ushort, :interface_number, :int,
                     :next, :pointer
            end
          end

          def devices
            @native.acquire
            owned = true
            pointer = @native.library.hid_enumerate(0x1050, 0)
            current = pointer
            found = []
            seen = {}
            until current.null?
              raise ResponseError, 'Invalid or oversized HID enumeration' if seen[current.address] || seen.length >= 1024

              seen[current.address] = true
              entry = @info.new(current)
              protocol = case [entry[:usage_page], entry[:usage]]
                         when [1, 6] then :otp
                         when [0xf1d0, 1] then :ctap
                         end
              if entry[:vendor_id] == 0x1050 && protocol
                found << {
                  backend: :hid, transport: :usb, protocol: protocol, device_path: string(entry[:path]),
                  serial: wide_string(entry[:serial_number]), vendor_id: entry[:vendor_id],
                  product_id: entry[:product_id], interface: entry[:interface_number],
                  product: wide_string(entry[:product_string])
                }
              end
              current = entry[:next]
            end
            completed = true
            found
          ensure
            primary_error = completed ? nil : $ERROR_INFO
            cleanup_error = nil
            begin
              @native.library.hid_free_enumeration(pointer) if pointer && !pointer.null?
            rescue Exception => e
              cleanup_error = e
            ensure
              begin
                @native.release if owned
              rescue Exception => e
                cleanup_error ||= e
              end
            end
            raise cleanup_error if cleanup_error && !primary_error
          end

          private

          def string(pointer)
            raise ResponseError, 'HID device has no path' if pointer.null?

            bytes = ''.b
            4096.times do |index|
              byte = pointer.get_uint8(index)
              return bytes if byte.zero?

              bytes << byte
            end
            raise ResponseError, 'Unterminated native device path'
          end

          def wide_string(pointer)
            return nil if pointer.null?

            windows = @native.platform == :windows
            units = []
            4096.times do |index|
              unit = windows ? pointer.get_uint16(index * 2) : pointer.get_uint32(index * 4)
              if unit.zero?
                return windows ? units.pack('v*').force_encoding(Encoding::UTF_16LE).encode(Encoding::UTF_8) : units.pack('U*')
              end

              units << unit
            end
            raise ResponseError, 'Unterminated native wide string'
          end
        end

        # One native handle; FFI buffers remain alive for the entire C call.
        class HIDIO
          def initialize(native, path)
            @native = native
            @native.acquire
            @owned = true
            @handle = @native.library.hid_open_path(path)
            raise CommandError, 'Cannot open selected HID device; check permissions and competing clients' if @handle.null?
          rescue Exception => e
            begin
              close
            rescue Exception
              # Acquisition failed; release errors must not hide that failure.
              nil
            end
            raise e
          end

          def write_packet(bytes)
            write(:hid_write, bytes, 64)
          end

          def write_feature(bytes)
            write(:hid_send_feature_report, bytes, 8)
          end

          def read_packet(milliseconds)
            buffer = ::FFI::MemoryPointer.new(:uchar, 64)
            count = @native.library.hid_read_timeout(@handle, buffer, 64, milliseconds)
            raise CommandError, 'HIDAPI read failed; device may be disconnected' if count.negative?
            raise ResponseError, 'Invalid HIDAPI input length' unless [0, 64].include?(count)

            buffer.read_bytes(count)
          end

          def read_feature
            buffer = ::FFI::MemoryPointer.new(:uchar, 9)
            count = @native.library.hid_get_feature_report(@handle, buffer, 9)
            raise CommandError, 'HIDAPI feature read failed' if count.negative?
            raise ResponseError, 'Invalid HIDAPI feature length or report ID' unless count == 9 && buffer.get_uint8(0).zero?

            buffer.get_bytes(1, 8)
          end

          def close
            return :closed unless @owned

            @owned = false
            begin
              @native.library.hid_close(@handle) if @handle && !@handle.null?
            ensure
              @native.release
            end
            :closed
          end

          private

          def write(function, bytes, size)
            raise ArgumentError, 'Invalid outgoing HID report size' unless bytes.bytesize == size

            wire = "\0".b + bytes
            buffer = ::FFI::MemoryPointer.new(:uchar, wire.bytesize)
            buffer.put_bytes(0, wire)
            count = @native.library.public_send(function, @handle, buffer, wire.bytesize)
            raise CommandError, 'HIDAPI write failed or was incomplete; command not retried' unless count == wire.bytesize

            :sent
          end
        end

        # Reader enumeration does not connect to cards or execute application APDUs.
        class PCSCInventory
          def initialize(native)
            @native = native
          end

          def devices
            context_ptr = ::FFI::MemoryPointer.new(@native.handle_type)
            check(@native.library.SCardEstablishContext(2, nil, nil, context_ptr))
            context = context_ptr.read(@native.handle_type)
            length = ::FFI::MemoryPointer.new(@native.dword)
            code = @native.library.SCardListReaders(context, nil, nil, length)
            return [] if (code & 0xffffffff) == 0x8010002e

            check(code)
            count = length.read(@native.dword)
            raise ResponseError, 'Invalid PC/SC reader list size' unless count.between?(2, 65_536)

            unit = @native.platform == :windows ? 2 : 1
            buffer = ::FFI::MemoryPointer.new(:uchar, count * unit)
            check(@native.library.SCardListReaders(context, nil, buffer, length))
            actual = length.read(@native.dword)
            raise ResponseError, 'PC/SC reader list grew; rerun discovery explicitly' unless actual.between?(2, count)

            bytes = buffer.read_bytes(actual * unit)
            text = unit == 2 ? bytes.force_encoding(Encoding::UTF_16LE).encode(Encoding::UTF_8) : bytes.force_encoding(Encoding::UTF_8)
            raise ResponseError, 'Invalid PC/SC reader list encoding or terminator' unless text.valid_encoding? && text.end_with?("\0\0")

            text.split("\0").map { |reader| { backend: :pcsc, protocol: :apdu, reader: reader, serial: nil } }
          ensure
            primary = $ERROR_INFO
            begin
              check(@native.library.SCardReleaseContext(context)) if context
            rescue StandardError
              raise unless primary
            end
          end

          private

          def check(code)
            raise CommandError, format('PC/SC reader discovery failed (0x%08x); check the PC/SC service', code & 0xffffffff) unless code.zero?
          end
        end

        # An exclusive PC/SC session never falls back to sharing with another client.
        class PCSCIO
          def initialize(native, reader)
            @native = native
            @context = establish
            handle = ::FFI::MemoryPointer.new(native.handle_type)
            active = ::FFI::MemoryPointer.new(native.dword)
            bytes = native.platform == :windows ? "#{reader.encode(Encoding::UTF_16LE).b}\0\0" : "#{reader.b}\0"
            name = ::FFI::MemoryPointer.new(:uchar, bytes.bytesize)
            name.put_bytes(0, bytes)
            check(native.library.SCardConnect(@context, name, 1, 3, handle, active), 'connect (exclusive; close competing clients)')
            @handle = handle.read(native.handle_type)
            @protocol = active.read(native.dword)
            raise ResponseError, 'PC/SC negotiated neither T=0 nor T=1' unless native.pci.key?(@protocol)
          rescue Exception => e
            begin
              close
            rescue Exception
              # Acquisition failed; release errors must not hide that failure.
              nil
            end
            raise e
          end

          def metadata
            atr = ::FFI::MemoryPointer.new(:uchar, 33)
            length = ::FFI::MemoryPointer.new(@native.dword)
            length.write(@native.dword, 33)
            check(@native.library.SCardGetAttrib(@handle, 0x00090303, atr, length), 'read ATR')
            count = length.read(@native.dword)
            raise ResponseError, 'Invalid smartcard ATR size' unless count.between?(2, 33)

            # Yubico's documented USB/NFC ATR distinction; not a vendor attestation.
            { transport: atr.get_uint8(1).allbits?(0xf0) ? :usb : :nfc }
          end

          def transmit(data)
            input = ::FFI::MemoryPointer.new(:uchar, data.bytesize)
            input.put_bytes(0, data)
            output = ::FFI::MemoryPointer.new(:uchar, 65_538)
            length = ::FFI::MemoryPointer.new(@native.dword)
            length.write(@native.dword, 65_538)
            check(@native.library.SCardTransmit(@handle, @native.pci.fetch(@protocol), input, data.bytesize, nil, output, length), 'transmit; command not retried')
            count = length.read(@native.dword)
            raise ResponseError, 'PC/SC returned a truncated or oversized R-APDU' unless count.between?(2, 65_538)

            output.read_bytes(count)
          end

          def close
            handle = @handle
            context = @context
            @handle = @context = nil
            begin
              check(@native.library.SCardDisconnect(handle, 0), 'disconnect') if handle
            ensure
              check(@native.library.SCardReleaseContext(context), 'release context') if context
            end
            :closed
          end

          private

          def establish
            context = ::FFI::MemoryPointer.new(@native.handle_type)
            check(@native.library.SCardEstablishContext(2, nil, nil, context), 'establish context; ensure the PC/SC service is running')
            context.read(@native.handle_type)
          end

          def check(code, operation)
            return :ok if code.zero?

            raise CommandError, format('PC/SC %<operation>s failed (0x%<code>08x)', operation: operation, code: code & 0xffffffff)
          end
        end

        # One monotonic budget covers INIT, packet writes, reads and touch waits.
        class Deadline
          def initialize(seconds, cancelled = nil)
            raise ArgumentError, 'timeout must be finite positive seconds' unless seconds.is_a?(Numeric) && seconds.real? && seconds.finite? && seconds.positive?

            @expires = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
            @cancelled = cancelled
            @stopped = false
          end

          def stop
            @stopped = true
          end

          def check!
            raise CancelledError, 'Device operation cancelled; do not retry uncertain writes' if @stopped || @cancelled&.call
            raise TimeoutError, 'Device operation timed out; do not retry uncertain writes' unless remaining.positive?
          end

          def remaining
            @expires - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          end

          def milliseconds
            check!
            (remaining * 1000).ceil.clamp(1, 50)
          end

          def pause(seconds)
            check!
            sleep(remaining.clamp(0, seconds))
            check!
          end
        end

        class CancelledError < Error
        end

        # Fixed-size YubiKey CTAPHID reports. Application status stays opaque.
        class CTAP
          MAX_PAYLOAD = 57 + (128 * 59)

          def initialize(io, descriptor)
            @io = io
            @descriptor = descriptor
            @channel = 0xffffffff
          end

          def prepare(deadline)
            initialize_channel(deadline) if @channel == 0xffffffff
          end

          def exchange(command, data, deadline, keepalive)
            prepare(deadline)
            send_message(command, data, deadline)
            receive_message(command, deadline, keepalive)
          rescue Exception
            # Cancellation is serialized behind the current native call; never
            # race hid_write/close against an in-flight C read on the handle.
            begin
              @io.write_packet([@channel, 0x91, 0].pack('NCn').ljust(64, "\0")) unless @channel == 0xffffffff
            rescue StandardError
              nil
            end
            raise
          end

          private

          def initialize_channel(deadline)
            nonce = SecureRandom.random_bytes(8)
            send_message(0x06, nonce, deadline)
            reply = receive_message(0x06, deadline, nil)
            raise ResponseError, 'Invalid CTAPHID INIT length or nonce' unless reply.bytesize == 17 && reply.byteslice(0, 8) == nonce

            channel, protocol, major, minor, patch, caps = reply.byteslice(8, 9).unpack('NCCCCC')
            raise ResponseError, 'Invalid CTAPHID channel or protocol' if [0, 0xffffffff].include?(channel) || protocol != 2

            @channel = channel
            @descriptor.merge!(channel: channel, version: [major, minor, patch], capabilities: caps)
          end

          def send_message(command, data, deadline)
            offset = 57
            deadline.check!
            @io.write_packet(([@channel, command | 0x80, data.bytesize].pack('NCn') + data.byteslice(0, 57)).ljust(64, "\0"))
            sequence = 0
            while offset < data.bytesize
              deadline.check!
              @io.write_packet(([@channel, sequence].pack('NC') + data.byteslice(offset, 59)).ljust(64, "\0"))
              offset += 59
              sequence += 1
            end
          end

          def receive_message(command, deadline, keepalive)
            response = ''.b
            length = nil
            sequence = 0
            loop do
              deadline.check!
              packet = @io.read_packet(deadline.milliseconds)
              next if packet.empty?
              raise ResponseError, 'Invalid CTAPHID report size' unless packet.bytesize == 64
              next unless packet.unpack1('N') == @channel

              marker = packet.getbyte(4)
              if length.nil?
                length = packet.byteslice(5, 2).unpack1('n')
                if marker == 0xbf
                  raise ResponseError, 'Invalid CTAPHID error length' unless length == 1

                  raise CommandError, format('CTAPHID error 0x%02x; command not retried', packet.getbyte(7))
                elsif marker == 0xbb
                  raise ResponseError, 'Invalid CTAPHID keepalive' unless length == 1 && [1, 2].include?(packet.getbyte(7))

                  keepalive&.call(packet.getbyte(7))
                  length = nil
                  next
                end
                raise ResponseError, 'Unexpected CTAPHID command or oversized message' unless marker == (command | 0x80) && length <= MAX_PAYLOAD

                response << packet.byteslice(7, [length, 57].min)
              else
                raise ResponseError, 'Out-of-order CTAPHID continuation' unless marker == sequence && sequence <= 127

                response << packet.byteslice(5, [length - response.bytesize, 59].min)
                sequence += 1
              end
              return response if response.bytesize == length
            end
          end
        end

        # OTP feature-report framing, distinct from the keyboard input endpoint.
        class OTP
          def initialize(io, descriptor)
            @io = io
            @descriptor = descriptor
          end

          def exchange(command, data, deadline, keepalive, expected = nil)
            status = report(deadline)
            @descriptor[:version] = status.byteslice(1, 3).bytes
            return status.byteslice(1, 6) if command.zero?

            previous = status.getbyte(4)
            payload = data.ljust(64, "\0")
            frame = payload + [command, crc(payload)].pack('Cv') + ("\0" * 3)
            10.times do |sequence|
              part = frame.byteslice(sequence * 7, 7)
              next if sequence != 0 && sequence != 9 && part.bytes.all?(&:zero?)

              deadline.pause(0.02) until report(deadline).getbyte(7).nobits?(0x80)
              deadline.check!
              @io.write_feature(part + [0x80 | sequence].pack('C'))
            end
            receive(previous, deadline, keepalive, expected)
          rescue Exception
            begin
              @io.write_feature(("\0" * 7) + "\xff".b) unless command.zero?
            rescue StandardError
              nil
            end
            raise
          end

          private

          def report(deadline)
            deadline.check!
            bytes = @io.read_feature
            raise ResponseError, 'Invalid OTP feature report size' unless bytes.bytesize == 8

            bytes
          end

          def crc(bytes)
            result = 0xffff
            bytes.each_byte do |byte|
              result ^= byte
              8.times { result = (result >> 1) ^ (result.odd? ? 0x8408 : 0) }
            end
            result
          end

          def receive(previous, deadline, keepalive, expected)
            sequence = 0
            payload = ''.b
            touched = false
            loop do
              bytes = report(deadline)
              flag = bytes.getbyte(7)
              if flag.anybits?(0x40)
                actual = flag & 0x1f
                if actual.zero? && sequence.positive?
                  @io.write_feature(("\0" * 7) + "\xff".b)
                  return checked_payload(payload, expected)
                end
                raise ResponseError, 'Out-of-order OTP response' unless actual == sequence && sequence < 32

                payload << bytes.byteslice(0, 7)
                sequence += 1
              elsif flag.zero?
                raise ResponseError, 'Truncated OTP response' unless payload.empty?

                next_sequence = bytes.getbyte(4)
                updated = next_sequence == previous + 1 || (next_sequence.zero? && previous.positive? && bytes.getbyte(5).nobits?(3))
                raise ResponseError, 'OTP returned status instead of the requested data' if updated && expected
                return bytes.byteslice(1, 6) if updated
                raise TimeoutError, 'OTP touch wait ended without confirmation' if touched

                raise CommandError, 'OTP command rejected or no response; command not retried'
              else
                touched ||= flag.anybits?(0x20)
                keepalive&.call(flag.anybits?(0x20) ? 2 : 1)
                deadline.pause(0.02)
              end
            end
          end

          def checked_payload(bytes, expected)
            if expected
              valid = bytes.bytesize >= expected + 2 && bytes.bytesize < expected + 9 && crc(bytes.byteslice(0, expected + 2)) == 0xf0b8
              raise ResponseError, 'Invalid OTP response length or CRC' unless valid

              return bytes.byteslice(0, expected)
            end

            # Without an expected length, only strip an unambiguous CRC followed
            # by at most six zero fill bytes in the final seven-byte packet.
            sizes = ([2, bytes.bytesize - 6].max..bytes.bytesize).select do |size|
              crc(bytes.byteslice(0, size)) == 0xf0b8 && bytes.byteslice(size..).bytes.all?(&:zero?)
            end
            raise ResponseError, 'Ambiguous or invalid OTP CRC; specify response_length' unless sizes.length == 1

            bytes.byteslice(0, sizes.first - 2)
          end
        end

        # A bounded Ruby waiter never kills a thread inside C. Drivers lacking a
        # native timeout may outlive the waiter; their owner retains buffers and
        # closes the handle only after the call returns (no use-after-free).
        class NativeTask
          attr_reader :thread

          def initialize(deadline)
            @deadline = deadline
            @result = Queue.new
          end

          def start(&work)
            @thread = Thread.new do
              @deadline.check!
              value = work.call
              @deadline.check!
              @result << [:ok, value]
            rescue Exception => e
              @result << [:error, e]
            end
            self
          end

          def await
            loop do
              @deadline.check!
              break if thread.join([@deadline.remaining, 0.01].min)
            end
            @deadline.check!
            kind, result = @result.pop
            raise result if kind == :error

            result
          rescue Exception
            @deadline.stop
            raise
          end
        end

        # The protocol-facing handle. Callers always supply a raw binary String.
        class Connection
          def initialize(descriptor:, io:, timeout: 30, prepare: nil)
            Deadline.new(timeout)
            @descriptor = descriptor.dup
            @descriptor.merge!(io.metadata) if io.respond_to?(:metadata)
            raise ArgumentError, 'Unknown transport protocol' unless %i[otp ctap apdu].include?(@descriptor[:protocol])

            @io = io
            @timeout = timeout
            @closed = false
            @state = Mutex.new
            @codec = case @descriptor[:protocol]
                     when :ctap then CTAP.new(io, @descriptor)
                     when :otp then OTP.new(io, @descriptor)
                     end
            @codec.prepare(prepare) if prepare && @descriptor[:protocol] == :ctap
          end

          def descriptor
            @descriptor.transform_values { |value| value.is_a?(String) || value.is_a?(Array) ? value.dup : value }
          end

          def exchange(opts = {})
            data = validate(opts)
            deadline = Deadline.new(opts.fetch(:timeout, @timeout), opts[:cancelled])
            deadline.check!
            task = @state.synchronize do
              raise Error, 'Connection is closed' if @closed
              raise CommandError, 'Another exchange is active on this connection' if @active

              @active = true
              @deadline = deadline
              @task = NativeTask.new(deadline).start do
                case @descriptor[:protocol]
                when :apdu then @io.transmit(data)
                when :ctap then @codec.exchange(opts[:command], data, deadline, opts[:on_keepalive])
                when :otp then @codec.exchange(opts[:command], data, deadline, opts[:on_keepalive], opts[:response_length])
                end
              end
            end
            begin
              task.await
            rescue Exception => e
              begin
                close
              rescue Exception
                # Keep the operation failure, including cancellation, authoritative.
                nil
              end
              raise e
            ensure
              @state.synchronize { @active = false }
            end
          end

          # Read-only identity probe, never authentication or a guessed serial.
          def identify_serial(deadline)
            if @descriptor[:protocol] == :apdu
              selected = exchange(protocol: :apdu, data: ['00a4040007a0000005272001'].pack('H*'), timeout: deadline.remaining)
              if selected.end_with?("\x90\x00".b)
                response = exchange(protocol: :apdu, data: ['0001100000'].pack('H*'), timeout: deadline.remaining)
                if response.end_with?("\x90\x00".b)
                  raise ResponseError, 'Invalid OTP serial response' unless response.bytesize == 6

                  serial = response.byteslice(0, 4).unpack1('N')
                  return @descriptor[:serial] = serial.to_s if serial.positive?
                end
              end
              @descriptor[:serial] = management_serial(deadline)
            elsif @descriptor[:protocol] == :otp
              response = exchange(protocol: :otp, command: 0x10, data: ''.b, response_length: 4, timeout: deadline.remaining)
              @descriptor[:serial] = response.unpack1('N').to_s
            end
          end

          def close
            cleanup = @state.synchronize do
              @closed = true
              @deadline&.stop
              @cleanup ||= Thread.new do
                @task&.thread&.join
                @io.close
                :closed
              rescue Exception => e
                e
              end
            end
            return :closing unless cleanup.join(0.05)

            result = cleanup.value
            raise result if result.is_a?(Exception)

            :closed
          end

          private

          def management_serial(deadline)
            selected = exchange(protocol: :apdu, data: ['00a4040008a000000527471117'].pack('H*'), timeout: deadline.remaining)
            return nil unless selected.end_with?("\x90\x00".b)

            require 'pwn/plugins/yubikey/protocol'
            data = Protocol.apdu(connection: self, ins: 0x1d, timeout: deadline.remaining, max_response: 256)
            raise ResponseError, 'Invalid management identity response length' if data.empty? || data.getbyte(0) != data.bytesize - 1

            serial = Protocol.tlv_map(data: data.byteslice(1..))[2]
            return nil unless serial
            raise ResponseError, 'Invalid management serial length' unless serial.bytesize == 4

            number = serial.unpack1('N')
            number.positive? ? number.to_s : nil
          end

          def validate(opts)
            raise Error, 'Connection is closed' if @closed

            data = opts.fetch(:data, ''.b)
            command = opts[:command]
            raise ArgumentError, 'data must be a String' unless data.is_a?(String)
            raise ArgumentError, 'protocol does not match this connection' unless opts[:protocol] == @descriptor[:protocol]

            %i[cancelled on_keepalive].each do |key|
              raise ArgumentError, "#{key} must be callable" unless opts[key].nil? || opts[key].respond_to?(:call)
            end
            case @descriptor[:protocol]
            when :apdu
              raise ArgumentError, 'C-APDU length must be in 4..65544' unless data.bytesize.between?(4, 65_544)
            when :ctap
              raise ArgumentError, 'CTAPHID command must be an integer in 1..127' unless command.is_a?(Integer) && command.between?(1, 127)
              raise ArgumentError, 'CTAPHID control command is reserved for the transport' if [0x06, 0x11, 0x3b, 0x3f].include?(command)
              raise ArgumentError, 'CTAPHID payload exceeds 7609 bytes' if data.bytesize > CTAP::MAX_PAYLOAD
            when :otp
              raise ArgumentError, 'OTP command must be a byte' unless command.is_a?(Integer) && command.between?(0, 255)
              raise ArgumentError, 'OTP payload exceeds 64 bytes' if data.bytesize > 64
              raise ArgumentError, 'OTP status command takes no data' if command.zero? && !data.empty?

              expected = opts[:response_length]
              raise ArgumentError, 'OTP response_length must be in 0..222' unless expected.nil? || (expected.is_a?(Integer) && expected.between?(0, 222))
            end
            data.b
          end
        end

        APPLICATIONS = %i[otp oath piv openpgp fido management hsmauth security_domain].freeze
        BINDING_LOCK = Mutex.new

        public_class_method def self.available?(opts = {})
          application = opts[:application]
          raise ArgumentError, 'Unknown YubiKey application' unless application.nil? || APPLICATIONS.include?(application)
          raise ArgumentError, 'backend must be :hid or :pcsc' unless opts[:backend].nil? || %i[hid pcsc].include?(opts[:backend])

          kinds = if opts[:backend]
                    [opts[:backend]]
                  elsif application && !%i[otp fido management].include?(application)
                    [:pcsc]
                  else
                    %i[hid pcsc]
                  end
          kinds.any? do |kind|
            native(kind: kind)
            true
          rescue DependencyError
            false
          end
        end

        public_class_method def self.devices(opts = {})
          validate_selection(opts)
          deadline = Deadline.new(opts.fetch(:timeout, 30))
          kinds = if opts[:backend]
                    [opts[:backend]]
                  else
                    (opts[:reader] ? [:pcsc] : %i[hid pcsc])
                  end
          missing = []
          records = kinds.flat_map do |kind|
            binding = native(kind: kind)
            entries = NativeTask.new(deadline).start { binding.devices }.await
            entries.select do |entry|
              (!opts[:serial] || entry[:serial] == opts[:serial]) &&
                (!opts[:reader] || entry[:reader] == opts[:reader]) &&
                (!opts[:device_path] || entry[:device_path] == opts[:device_path])
            end
          rescue DependencyError => e
            missing << e
            []
          end
          raise missing.first if missing.length == kinds.length

          records.uniq { |entry| [entry[:backend], entry[:protocol], entry[:device_path], entry[:reader]] }
        end

        public_class_method def self.open(opts = {})
          validate_selection(opts)
          application = opts[:application]
          raise ArgumentError, 'application must name a supported YubiKey application' unless APPLICATIONS.include?(application)

          deadline = Deadline.new(opts.fetch(:timeout, 30))
          order = if opts[:reader]
                    [:pcsc]
                  elsif opts[:device_path]
                    [:hid]
                  elsif %i[otp fido].include?(application)
                    %i[hid pcsc]
                  else
                    %i[pcsc hid]
                  end
          protocols = case application
                      when :otp then %i[otp apdu]
                      when :fido then %i[ctap apdu]
                      when :management then %i[apdu otp ctap]
                      else [:apdu]
                      end
          missing = []
          order.each do |kind|
            binding = native(kind: kind)
            entries = NativeTask.new(deadline).start { binding.devices }.await
            entries = entries.select do |entry|
              entry[:backend] == kind && protocols.include?(entry[:protocol]) &&
                (!opts[:serial] || entry[:serial].nil? || entry[:serial].empty? || entry[:serial] == opts[:serial]) &&
                (!opts[:device_path] || entry[:device_path] == opts[:device_path]) &&
                (opts[:reader] ? entry[:reader] == opts[:reader] : (kind != :pcsc || entry[:reader].match?(/yubikey/i)))
            end
            next if entries.empty?

            # Several application interfaces on one key are still not an excuse
            # to choose an arbitrary endpoint; prefer the documented protocol.
            preferred = protocols.find { |protocol| entries.any? { |entry| entry[:protocol] == protocol } }
            entries = entries.select { |entry| entry[:protocol] == preferred }
            if opts[:serial] && entries.any? { |entry| entry[:serial].nil? || entry[:serial].empty? }
              connection = select_serial(binding: binding, entries: entries, serial: opts[:serial], deadline: deadline, timeout: opts.fetch(:timeout, 30))
              return connection if connection

              next
            end
            raise Error, 'Multiple matching YubiKeys; specify exact serial, device_path or reader' unless entries.length == 1

            return acquire_connection(binding: binding, descriptor: entries.first, deadline: deadline, timeout: opts.fetch(:timeout, 30))
          rescue DependencyError => e
            missing << e
          end
          raise missing.first if missing.length == order.length

          raise Error, 'No matching YubiKey; check application mode, exact selectors, permissions, or specify the NFC reader'
        end

        public_class_method def self.authors(opts = {})
          opts[:format]
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help(opts = {})
          opts[:format]
          puts <<~HELP
            # Probe native shared libraries without device initialization or discovery.
            #{self}.available?(
              backend: 'optional - :hid or :pcsc; omitted accepts either suitable native library',
              application: 'optional - application Symbol; APDU-only applications require the PC/SC library'
            )
            # Enumerate interface descriptors without connecting to smartcards.
            #{self}.devices(
              backend: 'optional - :hid or :pcsc; defaults to both available libraries',
              serial: 'optional - exact observed HID serial String; reader serials are unknown until opened',
              reader: 'optional - exact PC/SC reader String for USB smartcard or NFC',
              device_path: 'optional - exact HIDAPI path String, including serial-less keys',
              timeout: 'optional - finite positive seconds, defaults to 30'
            )
            # Open one unambiguously selected native YubiKey application connection.
            #{self}.open(
              application: 'required - :otp, :oath, :piv, :openpgp, :fido, :management, :hsmauth or :security_domain',
              serial: 'optional - exact serial String; never coerced, trimmed or normalized',
              reader: 'optional - exact PC/SC reader String; forces smartcard transport',
              device_path: 'optional - exact HIDAPI path String; mutually exclusive with reader',
              timeout: 'optional - finite positive discovery and opening deadline in seconds, defaults to 30'
            )
            Connection#descriptor returns protocol :otp, :ctap or :apdu.
            Connection#exchange accepts protocol:, binary String data:, timeout: and optional cancelled: callable.
            OTP adds command: byte, response_length: optional payload byte count, on_keepalive: callback.
            OTP command 0 reads six status bytes without issuing a command. Other replies have CRC removed/checked.
            CTAP adds command: 1..127 (transport control commands reserved), on_keepalive: callback.
            CTAPHID INIT is completed by open; CBOR response retains its CTAP status byte.
            APDU returns the entire R-APDU including SW1/SW2. No automatic authentication, retry or logging occurs.
            Close in ensure. Connection#close is idempotent; :closing means deferred native cleanup.
            A timed-out blocking OS driver keeps its owned thread, buffers and handle until C returns.
            PC/SC SCardCancel does not portably abort SCardTransmit; no thread is killed inside C.
            # Return module author information.
            #{self}.authors(format: 'optional - reserved output format')
          HELP
        end

        private_class_method def self.validate_selection(opts = {})
          Deadline.new(opts.fetch(:timeout, 30))
          %i[serial reader device_path].each do |key|
            value = opts[key]
            next if value.nil?
            raise ArgumentError, "#{key} must be a nonempty exact String without NUL" unless value.is_a?(String) && !value.empty? && !value.include?("\0")
          end
          raise ArgumentError, 'reader and device_path cannot be combined' if opts[:reader] && opts[:device_path]
          raise ArgumentError, 'backend must be :hid or :pcsc' unless opts[:backend].nil? || %i[hid pcsc].include?(opts[:backend])
        end

        private_class_method def self.select_serial(opts = {})
          opened = []
          matches = opts[:entries].filter_map do |entry|
            conn = acquire_connection(binding: opts[:binding], descriptor: entry, deadline: opts[:deadline], timeout: opts[:timeout])
            opened << conn
            observed = entry[:serial]
            observed = conn.identify_serial(opts[:deadline]) if observed.nil? || observed.empty?
            observed == opts[:serial] ? conn : nil
          end
          raise Error, 'Multiple matching YubiKey serials; specify reader or device_path' if matches.length > 1

          chosen = matches.first
          chosen
        rescue Exception => e
          primary = e
          raise
        ensure
          cleanup_error = nil
          opened&.each do |conn|
            next if conn.equal?(chosen)

            begin
              conn.close
            rescue Exception => e
              cleanup_error ||= e
            end
          end
          if cleanup_error && !primary
            begin
              chosen&.close
            rescue Exception
              nil
            end
            raise cleanup_error
          end
        end

        private_class_method def self.acquire_connection(opts = {})
          io = nil
          deadline = opts[:deadline]
          task = NativeTask.new(deadline).start do
            io = opts[:binding].open(opts[:descriptor])
            Connection.new(descriptor: opts[:descriptor], io: io, timeout: opts[:timeout], prepare: deadline)
          end
          task.await
        rescue Exception
          deadline&.stop
          Thread.new do
            task&.thread&.join
            io&.close
          rescue StandardError
            nil
          end
          raise
        end

        private_class_method def self.native(opts = {})
          kind = opts[:kind]
          raise ArgumentError, 'backend must be :hid or :pcsc' unless %i[hid pcsc].include?(kind)

          BINDING_LOCK.synchronize do
            @bindings ||= {}
            @bindings[kind] ||= NativeLibrary.new(kind)
          end
        end
      end
    end
  end
end
# rubocop:enable Lint/RescueException
