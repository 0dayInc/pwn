# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'time'
require 'pwn/plugins/yubikey/protocol'
require 'pwn/plugins/yubikey/management'

module PWN
  module Plugins
    module YubiKey
      # Native OTP application protocol; no process or interpreter backend.
      # Wire references: Yubico OTP specifications / ykdef.h, and yubikit 5.9.1.
      module OTP
        AID = ['a0000005272001'].pack('H*').freeze
        GRAMMAR = {
          'info' => [0, [], []],
          'swap' => [0, %w[force], []],
          'delete' => [1, %w[force], []],
          'settings' => [1, %w[force delete-access-code enter no-enter use-numeric-keypad serial-usb-visible], %w[pacing]],
          'ndef' => [1, [], %w[prefix ndef-type]],
          'yubiotp' => [1, %w[enter no-enter serial-public-id generate-private-id generate-key upload force], %w[public-id config-output]],
          'static' => [1, %w[generate enter no-enter force], %w[length keyboard-layout]],
          'chalresp' => [1, %w[touch totp generate force], []],
          'calculate' => [2, %w[totp], %w[digits]],
          'hotp' => [1, %w[enter no-enter force], %w[digits counter identifier]]
        }.freeze
        ROUTES = { 'info' => :info, 'swap' => :swap, 'delete' => :delete_slot, 'settings' => :settings, 'ndef' => :configure_ndef, 'yubiotp' => :provision_yubiotp, 'static' => :provision_static, 'chalresp' => :provision_challenge_response, 'calculate' => :calculate, 'hotp' => :provision_hotp }.freeze

        public_class_method def self.operations(opts = {})
          opts[:format]
          GRAMMAR.keys
        end

        public_class_method def self.execute(opts = {})
          args = opts[:args] || []
          raise ArgumentError, 'args must be an Array of nonsecret Strings' unless args.is_a?(Array) && args.all?(String)
          return { application: :otp, operations: operations, secrets: :in_memory_only } if args.empty? || args == ['--help']

          operation = args.first
          grammar = GRAMMAR[operation]
          raise ArgumentError, 'Unknown OTP operation' unless grammar

          parsed = parse_arguments(args: args.drop(1), flags: grammar[1], values: grammar[2])
          positions = parsed[:positionals]
          limit = grammar[0]
          valid_count = operation == 'calculate' ? positions.length.between?(1, 2) : positions.length == limit
          raise ArgumentError, 'Invalid number of nonsecret OTP arguments; credentials belong in options' unless valid_count

          selected = opts.merge(parsed[:options])
          if limit.positive?
            raise ArgumentError, 'OTP slot must be 1 or 2' unless %w[1 2].include?(positions.first)

            selected[:slot] = positions.first.to_i
          end
          selected[:touch] = parsed[:options].fetch(:touch, opts.fetch(:touch, false)) if operation == 'chalresp'
          selected[:details] = true if operation == 'chalresp'
          selected[:challenge_argument] = positions[1] if operation == 'calculate'
          raise ArgumentError, 'Conflicting enter options' if selected[:enter] && selected[:no_enter]

          public_send(ROUTES.fetch(operation), selected)
        end

        public_class_method def self.info(opts = {})
          selected = { connection: opts[:connection], timeout: opts.fetch(:timeout, 30) }
          state = status(selected)
          if state[:version].first == 4
            metadata = Management.info(selected)
            if metadata[:is_fips]
              state = status(selected) if opts[:connection].descriptor[:protocol] == :apdu
              approved = transfer(selected.merge(command: 0x14, data: ''.b, response_length: 1))
              raise ResponseError, 'Invalid OTP FIPS approval response' unless ["\0".b, "\1".b].include?(approved)

              state = state.merge(fips_approved: approved == "\1".b)
            end
          end
          state
        end

        public_class_method def self.delete_slot(opts = {})
          slot = slot_number(slot: opts[:slot])
          consent(opts.merge(confirm: opts[:confirm]))
          access = access_codes(opts)
          before = status(opts)
          require_version(version: before[:version], minimum: [2, 1, 0])
          write_verified(opts.merge(slot: slot, command: slot == 1 ? 1 : 3, data: ("\0".b * 52) + access[:current], before: before, configured: false))
        end

        public_class_method def self.swap(opts = {})
          consent(opts.merge(confirm: opts[:confirm]))
          before = status(opts)
          require_version(version: before[:version], minimum: [2, 3, 0])
          result = write_verified(opts.merge(command: 6, data: "\0".b * 6, before: before))
          expected = ((before[:flags] & 1) << 1) | ((before[:flags] & 2) >> 1)
          raise ResponseError, 'OTP swap state uncertain: slot readback mismatch; do not replay' unless (result[:status][:flags] & 3) == expected

          result
        end

        public_class_method def self.settings(opts = {})
          slot = slot_number(slot: opts[:slot])
          consent(opts.merge(confirm: opts[:confirm]))
          raise ArgumentError, 'Conflicting access-code replacement options' if opts[:delete_access_code] && opts[:new_access_code]
          raise ArgumentError, 'Deleting access protection requires the current access_code' if opts[:delete_access_code] && !opts[:access_code]

          access = access_codes(opts.merge(new_access_code: opts[:delete_access_code] ? "\0".b * 6 : opts[:new_access_code]))
          fields = keyboard_flags(opts)
          config = pack_config(fields.merge(fixed: "\0".b * 16, uid: "\0".b * 6, key: "\0".b * 16, access_code: access[:new]))
          before = status(opts)
          require_version(version: before[:version], minimum: [2, 3, 0])
          raise CommandError, 'Cannot update an empty OTP slot' unless before[:slots][slot][:configured]
          raise CommandError, 'Firmware 4.3.2 through 4.3.5 cannot update access codes; no write attempted' if (before[:version] <=> [4, 3, 2]) >= 0 && (before[:version] <=> [4, 3, 6]).negative? && access[:new] != access[:current]

          write_verified(opts.merge(slot: slot, command: slot == 1 ? 4 : 5, data: config + access[:current], before: before, configured: true))
        end

        public_class_method def self.provision_yubiotp(opts = {})
          slot_number(slot: opts[:slot])
          consent(opts.merge(confirm: opts[:confirm]))
          raise ArgumentError, 'YubiCloud automated upload has ended; no network request is performed' if opts[:upload]
          raise ArgumentError, 'public_id and serial_public_id conflict' if opts[:public_id] && opts[:serial_public_id]

          fixed = opts[:public_id] ? modhex_decode(value: opts[:public_id]) : nil
          raise ArgumentError, 'public_id must contain at most 16 bytes' if fixed && fixed.bytesize > 16
          raise ArgumentError, 'public_id or serial_public_id is required' unless fixed || opts[:serial_public_id]

          uid = obtain_secret(opts.merge(name: :private_id, value: opts[:private_id], generate: opts[:generate_private_id], length: 6))
          key = obtain_secret(opts.merge(name: :key, value: opts[:key], generate: opts[:generate_key], length: 16))
          raise ArgumentError, 'private_id must contain six raw bytes and key sixteen raw bytes' unless uid.bytesize == 6 && key.bytesize == 16

          access_codes(opts)
          keyboard_flags(opts)
          export = open_export(path: opts[:config_output]) if opts[:config_output]
          serial = serial_number(opts) if opts[:serial_public_id] || export
          fixed ||= [0xff, 0].pack('C*') + [serial].pack('N')
          result = program_keyboard(opts.merge(fixed: fixed, uid: uid, key: key, mode_flags: 0))
          if export
            csv = "#{[serial.to_s, fixed.unpack1('H*').tr('0123456789abcdef', MODHEX), uid.unpack1('H*'), key.unpack1('H*'), (opts[:new_access_code] || opts[:access_code])&.unpack1('H*').to_s, Time.now.iso8601, ''].join(',')}\n"
            export.write(csv)
            export.flush
            export.fsync
            result = result.merge(configuration_exported: true)
          end
          result
        rescue IOError, SystemCallError
          raise ResponseError, 'OTP programming/export incomplete; inspect the exact slot and private output file before retrying', cause: nil
        ensure
          export&.close
        end

        public_class_method def self.provision_static(opts = {})
          slot_number(slot: opts[:slot])
          consent(opts.merge(confirm: opts[:confirm]))
          layout = opts.fetch(:keyboard_layout, 'MODHEX').to_s.upcase
          map = scan_map(layout: layout)
          length = strict_integer(value: opts.fetch(:length, 38), minimum: 1, maximum: 38)
          if opts[:generate]
            raise ArgumentError, 'generate conflicts with password' if opts[:password]
            raise ArgumentError, 'Generated credentials require an explicit secret_sink callable' unless opts[:secret_sink].respond_to?(:call)

            alphabet = map.keys.grep_v(/\s/)
            password = Array.new(length) { alphabet[SecureRandom.random_number(alphabet.length)] }.join
            opts[:secret_sink].call(:password, password.dup)
          else
            password = secret_value(opts.merge(name: :password, value: opts[:password])).force_encoding(Encoding::UTF_8)
          end
          raise ArgumentError, 'password must contain 1 to 38 supported characters' unless password.valid_encoding? && password.length.between?(1, 38)

          codes = password.each_char.map do |char|
            raise ArgumentError, 'Password contains a character unavailable in the selected keyboard layout' unless map.key?(char)

            map[char]
          end.pack('C*').ljust(38, "\0")
          program_keyboard(opts.merge(fixed: codes.byteslice(0, 16), uid: codes.byteslice(16, 6), key: codes.byteslice(22, 16), mode_flags: 2))
        end

        public_class_method def self.provision_hotp(opts = {})
          slot_number(slot: opts[:slot])
          consent(opts.merge(confirm: opts[:confirm]))
          digits = strict_integer(value: opts.fetch(:digits, 6), minimum: 6, maximum: 8)
          raise ArgumentError, 'HOTP digits must be 6 or 8' unless [6, 8].include?(digits)

          counter = strict_integer(value: opts.fetch(:counter, 0), minimum: 0, maximum: 0xffff0)
          raise ArgumentError, 'HOTP counter must be divisible by 16' unless (counter % 16).zero?

          identifier = hotp_identifier(opts.merge(identifier: opts[:identifier]))
          key = secret_value(opts.merge(name: :key, value: opts[:key]))
          key = OpenSSL::Digest::SHA1.digest(key) if key.bytesize > 64
          raise ArgumentError, 'HOTP key must contain 1 to 20 bytes, or more than 64 bytes' unless key.bytesize.between?(1, 20)

          uid = key.byteslice(16..).to_s.b.ljust(4, "\0") + [counter >> 4].pack('n')
          program_keyboard(opts.merge(fixed: identifier[:fixed], uid: uid, key: key.byteslice(0, 16).ljust(16, "\0"), mode_flags: identifier[:flags] | (digits == 8 ? 2 : 0), ticket_flags: 0x40))
        end

        public_class_method def self.configure_ndef(opts = {})
          slot = slot_number(slot: opts[:slot])
          consent(opts.merge(confirm: opts[:confirm]))
          type = opts.fetch(:ndef_type, 'URI').to_s.upcase
          raise ArgumentError, 'ndef_type must be URI or TEXT' unless %w[URI TEXT].include?(type)

          prefix = opts.fetch(:prefix, type == 'URI' ? 'https://my.yubico.com/yk/#' : '')
          raise ArgumentError, 'NDEF prefix must be a valid UTF8 String' unless prefix.is_a?(String) && prefix.encoding == Encoding::UTF_8 && prefix.valid_encoding?

          payload = if type == 'TEXT'
                      "\2en".b + prefix.b
                    else
                      index = NDEF_PREFIXES.index { |candidate| prefix.start_with?(candidate) }
                      index ? [index + 1].pack('C') + prefix.delete_prefix(NDEF_PREFIXES[index]).b : "\0".b + prefix.b
                    end
          raise ArgumentError, 'NDEF payload must not exceed 54 bytes' if payload.bytesize > 54

          access = access_codes(opts)
          validate_nfc(connection: opts[:connection], timeout: opts.fetch(:timeout, 30))
          before = status(opts)
          require_version(version: before[:version], minimum: [3, 0, 0])
          raise CommandError, 'NDEF requires a configured slot' unless before[:slots][slot][:configured]
          raise CommandError, 'NDEF is unavailable on this device' if opts[:connection].descriptor[:nfc] == false

          data = [payload.bytesize, type == 'URI' ? 0x55 : 0x54].pack('C*') + payload.ljust(54, "\0") + access[:current]
          write_verified(opts.merge(slot: slot, command: slot == 1 ? 8 : 9, data: data, before: before, configured: true))
        end

        public_class_method def self.calculate(opts = {})
          argument = opts[:challenge_argument]
          if opts[:totp]
            digits = strict_integer(value: opts.fetch(:digits, 6), minimum: 6, maximum: 8)
            raise ArgumentError, 'TOTP digits must be 6 or 8' unless [6, 8].include?(digits)

            timestamp = strict_integer(value: argument || opts.fetch(:timestamp) { Time.now.to_i }, minimum: 0, maximum: 0xffffffffffffffff)
            challenge = [timestamp / 30].pack('Q>')
          else
            challenge = opts[:challenge]
            if argument
              raise ArgumentError, 'Challenge argument must be an even-length hexadecimal String' unless argument.match?(/\A(?:[0-9a-fA-F]{2}){1,64}\z/)

              challenge = [argument].pack('H*')
            end
          end
          response = challenge_response(opts.merge(challenge: challenge))
          return response unless opts[:totp]

          offset = response.getbyte(19) & 15
          value = response.byteslice(offset, 4).unpack1('N') & 0x7fffffff
          (value % (10**digits)).to_s.rjust(digits, '0')
        end

        NDEF_PREFIXES = %w[http://www. https://www. http:// https:// tel: mailto: ftp://anonymous:anonymous@ ftp://ftp. ftps:// sftp:// smb:// nfs:// ftp:// dav:// news: telnet:// imap: rtsp:// urn: pop: sip: sips: tftp: btspp:// btl2cap:// btgoep:// tcpobex:// irdaobex:// file:// urn:epc:id: urn:epc:tag: urn:epc:pat: urn:epc:raw: urn:epc: urn:nfc:].freeze
        # Keyboard layout data adapted from yubikey-manager 5.9.1.
        # Copyright (c) 2018 Yubico AB. All rights reserved.
        # Redistribution and use in source and binary forms, with or without
        # modification, are permitted provided that the following conditions are met:
        # 1. Redistributions of source code must retain the above copyright notice,
        #    this list of conditions and the following disclaimer.
        # 2. Redistributions in binary form must reproduce the above copyright
        #    notice, this list of conditions and the following disclaimer in the
        #    documentation and/or other materials provided with the distribution.
        # THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
        # AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
        # IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
        # ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
        # LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
        # CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
        # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
        # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
        # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
        # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
        # POSSIBILITY OF SUCH DAMAGE.

        KEYBOARD_LAYOUTS = {
          'US' => {
            97 => 0x04, 98 => 0x05, 99 => 0x06, 100 => 0x07, 101 => 0x08, 102 => 0x09, 103 => 0x0a, 104 => 0x0b,
            105 => 0x0c, 106 => 0x0d, 107 => 0x0e, 108 => 0x0f, 109 => 0x10, 110 => 0x11, 111 => 0x12, 112 => 0x13,
            113 => 0x14, 114 => 0x15, 115 => 0x16, 116 => 0x17, 117 => 0x18, 118 => 0x19, 119 => 0x1a, 120 => 0x1b,
            121 => 0x1c, 122 => 0x1d, 65 => 0x84, 66 => 0x85, 67 => 0x86, 68 => 0x87, 69 => 0x88, 70 => 0x89,
            71 => 0x8a, 72 => 0x8b, 73 => 0x8c, 74 => 0x8d, 75 => 0x8e, 76 => 0x8f, 77 => 0x90, 78 => 0x91,
            79 => 0x92, 80 => 0x93, 81 => 0x94, 82 => 0x95, 83 => 0x96, 84 => 0x97, 85 => 0x98, 86 => 0x99,
            87 => 0x9a, 88 => 0x9b, 89 => 0x9c, 90 => 0x9d, 48 => 0x27, 49 => 0x1e, 50 => 0x1f, 51 => 0x20,
            52 => 0x21, 53 => 0x22, 54 => 0x23, 55 => 0x24, 56 => 0x25, 57 => 0x26, 9 => 0x2b, 10 => 0x28,
            33 => 0x9e, 34 => 0xb4, 35 => 0xa0, 36 => 0xa1, 37 => 0xa2, 38 => 0xa4, 39 => 0x34, 96 => 0x35,
            40 => 0xa6, 41 => 0xa7, 42 => 0xa5, 43 => 0xae, 44 => 0x36, 45 => 0x2d, 46 => 0x37, 47 => 0x38,
            58 => 0xb3, 59 => 0x33, 60 => 0xb6, 61 => 0x2e, 62 => 0xb7, 63 => 0xb8, 64 => 0x9f, 91 => 0x2f,
            92 => 0x32, 93 => 0x30, 94 => 0xa3, 95 => 0xad, 123 => 0xaf, 125 => 0xb0, 124 => 0xb2, 126 => 0xb5,
            32 => 0x2c
          },
          'MODHEX' => {
            98 => 0x05, 99 => 0x06, 100 => 0x07, 101 => 0x08, 102 => 0x09, 103 => 0x0a, 104 => 0x0b, 105 => 0x0c,
            106 => 0x0d, 107 => 0x0e, 108 => 0x0f, 110 => 0x11, 114 => 0x15, 116 => 0x17, 117 => 0x18, 118 => 0x19,
            66 => 0x85, 67 => 0x86, 68 => 0x87, 69 => 0x88, 70 => 0x89, 71 => 0x8a, 72 => 0x8b, 73 => 0x8c,
            74 => 0x8d, 75 => 0x8e, 76 => 0x8f, 78 => 0x91, 82 => 0x95, 84 => 0x97, 85 => 0x98, 86 => 0x99
          },
          'UK' => {
            97 => 0x04, 98 => 0x05, 99 => 0x06, 100 => 0x07, 101 => 0x08, 102 => 0x09, 103 => 0x0a, 104 => 0x0b,
            105 => 0x0c, 106 => 0x0d, 107 => 0x0e, 108 => 0x0f, 109 => 0x10, 110 => 0x11, 111 => 0x12, 112 => 0x13,
            113 => 0x14, 114 => 0x15, 115 => 0x16, 116 => 0x17, 117 => 0x18, 118 => 0x19, 119 => 0x1a, 120 => 0x1b,
            121 => 0x1c, 122 => 0x1d, 65 => 0x84, 66 => 0x85, 67 => 0x86, 68 => 0x87, 69 => 0x88, 70 => 0x89,
            71 => 0x8a, 72 => 0x8b, 73 => 0x8c, 74 => 0x8d, 75 => 0x8e, 76 => 0x8f, 77 => 0x90, 78 => 0x91,
            79 => 0x92, 80 => 0x93, 81 => 0x94, 82 => 0x95, 83 => 0x96, 84 => 0x97, 85 => 0x98, 86 => 0x99,
            87 => 0x9a, 88 => 0x9b, 89 => 0x9c, 90 => 0x9d, 48 => 0x27, 49 => 0x1e, 50 => 0x1f, 51 => 0x20,
            52 => 0x21, 53 => 0x22, 54 => 0x23, 55 => 0x24, 56 => 0x25, 57 => 0x26, 9 => 0x2b, 10 => 0x28,
            33 => 0x9e, 64 => 0xb4, 163 => 0xa0, 36 => 0xa1, 37 => 0xa2, 38 => 0xa4, 39 => 0x34, 96 => 0x35,
            40 => 0xa6, 41 => 0xa7, 42 => 0xa5, 43 => 0xae, 44 => 0x36, 45 => 0x2d, 46 => 0x37, 47 => 0x38,
            58 => 0xb3, 59 => 0x33, 60 => 0xb6, 61 => 0x2e, 62 => 0xb7, 63 => 0xb8, 34 => 0x9f, 91 => 0x2f,
            35 => 0x32, 93 => 0x30, 94 => 0xa3, 95 => 0xad, 123 => 0xaf, 125 => 0xb0, 126 => 0xb2, 172 => 0xb5,
            32 => 0x2c
          },
          'DE' => {
            97 => 0x04, 98 => 0x05, 99 => 0x06, 100 => 0x07, 101 => 0x08, 102 => 0x09, 103 => 0x0a, 104 => 0x0b,
            105 => 0x0c, 106 => 0x0d, 107 => 0x0e, 108 => 0x0f, 109 => 0x10, 110 => 0x11, 111 => 0x12, 112 => 0x13,
            113 => 0x14, 114 => 0x15, 115 => 0x16, 116 => 0x17, 117 => 0x18, 118 => 0x19, 119 => 0x1a, 120 => 0x1b,
            121 => 0x1d, 122 => 0x1c, 65 => 0x84, 66 => 0x85, 67 => 0x86, 68 => 0x87, 69 => 0x88, 70 => 0x89,
            71 => 0x8a, 72 => 0x8b, 73 => 0x8c, 74 => 0x8d, 75 => 0x8e, 76 => 0x8f, 77 => 0x90, 78 => 0x91,
            79 => 0x92, 80 => 0x93, 81 => 0x94, 82 => 0x95, 83 => 0x96, 84 => 0x97, 85 => 0x98, 86 => 0x99,
            87 => 0x9a, 88 => 0x9b, 89 => 0x9d, 90 => 0x9c, 48 => 0x27, 49 => 0x1e, 50 => 0x1f, 51 => 0x20,
            52 => 0x21, 53 => 0x22, 54 => 0x23, 55 => 0x24, 56 => 0x25, 57 => 0x26, 9 => 0x2b, 10 => 0x28,
            33 => 0x9e, 34 => 0x9f, 35 => 0x32, 36 => 0xa1, 37 => 0xa2, 38 => 0xa3, 39 => 0xb2, 40 => 0xa5,
            41 => 0xa6, 42 => 0xb0, 43 => 0x30, 44 => 0x36, 45 => 0x38, 46 => 0x37, 47 => 0xa4, 58 => 0xb7,
            59 => 0xb6, 60 => 0x64, 61 => 0xa7, 62 => 0xe4, 63 => 0xad, 94 => 0x35, 95 => 0xb8, 32 => 0x2c,
            96 => 0xad, 167 => 0xa0, 180 => 0x2e, 196 => 0xb4, 214 => 0xb3, 220 => 0xaf, 223 => 0x2d, 228 => 0x34,
            246 => 0x33, 252 => 0x2f
          },
          'FR' => {
            97 => 0x14, 98 => 0x05, 99 => 0x06, 100 => 0x07, 101 => 0x08, 102 => 0x09, 103 => 0x0a, 104 => 0x0b,
            105 => 0x0c, 106 => 0x0d, 107 => 0x0e, 108 => 0x0f, 109 => 0x33, 110 => 0x11, 111 => 0x12, 112 => 0x13,
            113 => 0x04, 114 => 0x15, 115 => 0x16, 116 => 0x17, 117 => 0x18, 118 => 0x19, 119 => 0x1d, 120 => 0x1b,
            121 => 0x1c, 122 => 0x1a, 65 => 0x94, 66 => 0x85, 67 => 0x86, 68 => 0x87, 69 => 0x88, 70 => 0x89,
            71 => 0x8a, 72 => 0x8b, 73 => 0x8c, 74 => 0x8d, 75 => 0x8e, 76 => 0x8f, 77 => 0xb3, 78 => 0x91,
            79 => 0x92, 80 => 0x93, 81 => 0x84, 82 => 0x95, 83 => 0x96, 84 => 0x97, 85 => 0x98, 86 => 0x99,
            87 => 0x9d, 88 => 0x9b, 89 => 0x9c, 90 => 0x9a, 48 => 0xa7, 49 => 0x9e, 50 => 0x9f, 51 => 0xa0,
            52 => 0xa1, 53 => 0xa2, 54 => 0xa3, 55 => 0xa4, 56 => 0xa5, 57 => 0xa6, 9 => 0x2b, 10 => 0x28,
            32 => 0x2c, 33 => 0x38, 34 => 0x20, 36 => 0x30, 37 => 0xb4, 38 => 0x1e, 39 => 0x21, 40 => 0x22,
            41 => 0x2d, 42 => 0x31, 43 => 0xae, 44 => 0x10, 45 => 0x23, 46 => 0xb6, 47 => 0xb7, 58 => 0x37,
            59 => 0x36, 60 => 0x64, 61 => 0x2e, 95 => 0x25, 127 => 0x2a, 163 => 0xb0, 167 => 0xb8, 176 => 0xad,
            178 => 0x35, 181 => 0xb1, 224 => 0x27, 231 => 0x26, 232 => 0x24, 233 => 0x1f, 249 => 0x34
          },
          'IT' => {
            9 => 0x2b, 10 => 0x28, 32 => 0x2c, 33 => 0x9e, 34 => 0x9f, 35 => 0x32, 36 => 0xa1, 37 => 0xa2,
            38 => 0xa3, 39 => 0x2d, 40 => 0xa5, 41 => 0xa6, 42 => 0x55, 43 => 0x30, 44 => 0x36, 45 => 0x38,
            46 => 0x63, 47 => 0xa4, 48 => 0x27, 49 => 0x1e, 50 => 0x1f, 51 => 0x20, 52 => 0x21, 53 => 0x22,
            54 => 0x23, 55 => 0x24, 56 => 0x25, 57 => 0x26, 58 => 0xb7, 59 => 0xb6, 60 => 0x64, 61 => 0xa7,
            62 => 0xe4, 63 => 0xad, 64 => 0x24, 65 => 0x84, 66 => 0x85, 67 => 0x86, 68 => 0x87, 69 => 0x88,
            70 => 0x89, 71 => 0x8a, 72 => 0x8b, 73 => 0x8c, 74 => 0x8d, 75 => 0x8e, 76 => 0x8f, 77 => 0x90,
            78 => 0x91, 79 => 0x92, 80 => 0x93, 81 => 0x94, 82 => 0x95, 83 => 0x96, 84 => 0x97, 85 => 0x98,
            86 => 0x99, 87 => 0x9a, 88 => 0x9b, 89 => 0x9c, 90 => 0x9d, 92 => 0x35, 94 => 0xae, 95 => 0xb8,
            96 => 0xad, 97 => 0x04, 98 => 0x05, 99 => 0x06, 100 => 0x07, 101 => 0x08, 102 => 0x09, 103 => 0x0a,
            104 => 0x0b, 105 => 0x0c, 106 => 0x0d, 107 => 0x0e, 108 => 0x0f, 109 => 0x10, 110 => 0x11, 111 => 0x12,
            112 => 0x13, 113 => 0x14, 114 => 0x15, 115 => 0x16, 116 => 0x17, 117 => 0x18, 118 => 0x19, 119 => 0x1a,
            120 => 0x1b, 121 => 0x1c, 122 => 0x1d, 124 => 0xb5, 163 => 0xa0, 167 => 0xb2, 176 => 0xb4, 231 => 0xb3,
            232 => 0x2f, 233 => 0xaf, 224 => 0x34, 236 => 0x2e, 242 => 0x33, 249 => 0x31
          },
          'BEPO' => {
            9 => 0xab, 10 => 0xa8, 32 => 0x2c, 33 => 0x9c, 34 => 0x1e, 35 => 0xb5, 36 => 0x35, 37 => 0x2e,
            39 => 0x11, 40 => 0x21, 41 => 0x22, 42 => 0x27, 43 => 0x24, 44 => 0x0a, 45 => 0x25, 46 => 0x19,
            47 => 0x26, 48 => 0xa7, 49 => 0x9e, 50 => 0x9f, 51 => 0xa0, 52 => 0xa1, 53 => 0xa2, 54 => 0xa3,
            55 => 0xa4, 56 => 0xa5, 57 => 0xa6, 58 => 0x99, 59 => 0x8a, 61 => 0x2d, 63 => 0x91, 64 => 0x23,
            65 => 0x84, 66 => 0x94, 67 => 0x8b, 68 => 0x8c, 69 => 0x89, 70 => 0xb8, 71 => 0xb6, 72 => 0xb7,
            73 => 0x87, 74 => 0x93, 75 => 0x85, 76 => 0x92, 77 => 0xb4, 78 => 0xb3, 79 => 0x95, 80 => 0x88,
            81 => 0x90, 82 => 0x8f, 83 => 0x8e, 84 => 0x8d, 85 => 0x96, 86 => 0x98, 87 => 0xb0, 88 => 0x86,
            89 => 0x9b, 90 => 0xaf, 96 => 0xae, 97 => 0x04, 98 => 0x14, 99 => 0x0b, 100 => 0x0c, 101 => 0x09,
            102 => 0x38, 103 => 0x36, 104 => 0x37, 105 => 0x07, 106 => 0x13, 107 => 0x05, 108 => 0x12, 109 => 0x34,
            110 => 0x33, 111 => 0x15, 112 => 0x08, 113 => 0x10, 114 => 0x0f, 115 => 0x0e, 116 => 0x0d, 117 => 0x16,
            118 => 0x18, 119 => 0x30, 120 => 0x06, 121 => 0x1b, 122 => 0x2f, 160 => 0xac, 171 => 0x1f, 176 => 0xad,
            187 => 0x20, 192 => 0x9d, 199 => 0xb1, 200 => 0x97, 201 => 0x9a, 202 => 0xe4, 224 => 0x1d, 231 => 0x31,
            232 => 0x17, 233 => 0x1a, 234 => 0x64
          },
          'NORMAN' => {
            97 => 0x04, 98 => 0x05, 99 => 0x06, 100 => 0x08, 101 => 0x07, 102 => 0x15, 103 => 0x0a, 104 => 0x33,
            105 => 0x0e, 106 => 0x1c, 107 => 0x17, 108 => 0x12, 109 => 0x10, 110 => 0x0d, 111 => 0x0f, 112 => 0x11,
            113 => 0x14, 114 => 0x0c, 115 => 0x16, 116 => 0x09, 117 => 0x18, 118 => 0x19, 119 => 0x1a, 120 => 0x1b,
            121 => 0x0b, 122 => 0x1d, 65 => 0x84, 66 => 0x85, 67 => 0x86, 68 => 0x88, 69 => 0x87, 70 => 0x95,
            71 => 0x8a, 72 => 0xb3, 73 => 0x8e, 74 => 0x9c, 75 => 0x97, 76 => 0x92, 77 => 0x90, 78 => 0x8d,
            79 => 0x8f, 80 => 0x91, 81 => 0x94, 82 => 0x8c, 83 => 0x96, 84 => 0x89, 85 => 0x98, 86 => 0x99,
            87 => 0x9a, 88 => 0x9b, 89 => 0x8b, 90 => 0x9d, 48 => 0x27, 49 => 0x1e, 50 => 0x1f, 51 => 0x20,
            52 => 0x21, 53 => 0x22, 54 => 0x23, 55 => 0x24, 56 => 0x25, 57 => 0x26, 9 => 0x2b, 10 => 0x28,
            33 => 0x9e, 34 => 0xb4, 35 => 0xa0, 36 => 0xa1, 37 => 0xa2, 38 => 0xa4, 39 => 0x34, 96 => 0x35,
            40 => 0xa6, 41 => 0xa7, 42 => 0xa5, 43 => 0xae, 44 => 0x36, 45 => 0x2d, 46 => 0x37, 47 => 0x38,
            58 => 0xb3, 59 => 0x13, 60 => 0xb6, 61 => 0x2e, 62 => 0xb7, 63 => 0xb8, 64 => 0x9f, 91 => 0x2f,
            92 => 0x32, 93 => 0x30, 94 => 0xa3, 95 => 0xad, 123 => 0xaf, 125 => 0xb0, 124 => 0xb2, 126 => 0xb5,
            32 => 0x2c
          }
        }.transform_values { |mapping| mapping.transform_keys { |codepoint| codepoint.chr(Encoding::UTF_8) }.freeze }.freeze

        MODHEX = 'cbdefghijklnrtuv'

        private_class_method def self.program_keyboard(opts = {})
          slot = opts[:slot]
          access = access_codes(opts)
          fields = keyboard_flags(opts)
          fields[:cfg] |= opts[:mode_flags]
          fields[:tkt] |= opts.fetch(:ticket_flags, 0)
          config = pack_config(fields.merge(fixed: opts[:fixed], uid: opts[:uid], key: opts[:key], access_code: access[:new]))
          before = status(opts)
          require_version(version: before[:version], minimum: [2, 2, 0])
          write_verified(opts.merge(command: slot == 1 ? 1 : 3, data: config + access[:current], before: before, configured: true))
        end

        private_class_method def self.hotp_identifier(opts = {})
          value = opts[:identifier]
          return { fixed: ''.b, flags: 0 } if value.nil?
          raise ArgumentError, 'identifier must be a String' unless value.is_a?(String)

          value = 'ubhe' if value == '-'
          value += format('%08d', serial_number(opts)) if value.length == 4
          value = "ubhe#{value}" if value.length == 8
          raise ArgumentError, 'identifier must encode 12 modhex/BCD characters' unless value.length == 12

          parts = [value[0, 2], value[2, 2], value[4, 8]]
          modes = parts.map { |part| part.each_char.all? { |char| MODHEX.include?(char) } }
          raise ArgumentError, 'Identifier modhex components must form a leading prefix' if (!modes[0] && modes[1]) || (modes[2] && !modes.take(2).all?)

          fixed = parts.each_with_index.map do |part, index|
            next modhex_decode(value: part) if modes[index]
            raise ArgumentError, 'Identifier component is neither modhex nor BCD' unless part.match?(/\A[0-9]+\z/)

            [part].pack('H*')
          end.join.b
          { fixed: fixed, flags: if modes[2]
                                   0x50
                                 elsif modes[1]
                                   0x40
                                 else
                                   modes[0] ? 0x10 : 0
                                 end }
        end

        private_class_method def self.modhex_decode(opts = {})
          value = opts[:value]
          raise ArgumentError, 'public_id must be even-length lowercase modhex' unless value.is_a?(String) && value.match?(/\A(?:[cbdefghijklnrtuv]{2})*\z/)

          [value.tr(MODHEX, '0123456789abcdef')].pack('H*')
        end

        private_class_method def self.serial_number(opts = {})
          status(opts)
          raw = transfer(opts.merge(command: 0x10, data: ''.b, response_length: 4))
          raise ResponseError, 'Device serial is unavailable' unless raw.is_a?(String) && raw.bytesize == 4 && raw.unpack1('N').positive?

          raw.unpack1('N')
        end

        private_class_method def self.strict_integer(opts = {})
          value = opts[:value]
          raise ArgumentError, 'Expected an unsigned decimal integer' unless value.is_a?(Integer) || (value.is_a?(String) && value.match?(/\A[0-9]+\z/))

          value = value.to_i
          raise ArgumentError, 'Numeric option outside its supported range' unless value.between?(opts[:minimum], opts[:maximum])

          value
        end

        private_class_method def self.open_export(opts = {})
          path = opts[:path]
          raise ArgumentError, 'config_output must be an explicit nonempty file path' unless path.is_a?(String) && !path.empty? && !path.include?("\0")
          raise DependencyError, 'Secure configuration export requires no-follow file support' unless File.const_defined?(:NOFOLLOW)

          # Returned handle is owned and closed by provision_yubiotp's ensure.
          file = File.open(path, File::WRONLY | File::CREAT | File::APPEND | File::NOFOLLOW | File::NONBLOCK, 0o600) # rubocop:disable Style/FileOpen
          stat = file.stat
          unless stat.file? && stat.nlink == 1 && stat.uid == Process.euid && stat.mode.nobits?(0o077) && file.flock(File::LOCK_EX | File::LOCK_NB)
            file.close
            raise ArgumentError, 'Configuration export requires an owned private regular file without other links or writers'
          end
          checked = true
          file
        ensure
          file.close if file && !checked && !file.closed?
        end

        private_class_method def self.decode_secret(opts = {})
          key = opts[:key]
          case opts.fetch(:encoding, :raw).to_s
          when 'raw'
            key
          when 'hex'
            raise ArgumentError, 'Encoded key must contain an even number of hexadecimal digits' unless key.match?(/\A(?:[0-9a-fA-F]{2})+\z/)

            [key].pack('H*')
          when 'base32'
            text = key.upcase
            raise ArgumentError, 'Encoded key is not canonical Base32' unless text.match?(/\A[A-Z2-7]+={0,6}\z/)

            bare = text.delete_suffix('=' * text.count('='))
            raise ArgumentError, 'Invalid Base32 key length or padding' unless [0, 2, 4, 5, 7].include?(bare.length % 8) && (!text.include?('=') || (text.length % 8).zero?)

            alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
            bits = bare.each_char.map { |char| alphabet.index(char).to_s(2).rjust(5, '0') }.join
            whole = (bits.length / 8) * 8
            raise ArgumentError, 'Base32 key has nonzero unused bits' if bits[whole..].include?('1')

            [bits[0, whole]].pack('B*')
          else
            raise ArgumentError, 'key_encoding must be raw, hex or base32'
          end
        end

        private_class_method def self.obtain_secret(opts = {})
          if opts[:generate]
            raise ArgumentError, 'Generation conflicts with the provided secret' if opts[:value]
            raise ArgumentError, 'Generated credentials require an explicit secret_sink callable' unless opts[:secret_sink].respond_to?(:call)

            value = SecureRandom.random_bytes(opts[:length])
            opts[:secret_sink].call(opts[:name], value.dup)
            value
          else
            secret_value(opts)
          end
        end

        private_class_method def self.scan_map(opts = {})
          map = KEYBOARD_LAYOUTS[opts[:layout]]
          raise ArgumentError, 'Unsupported keyboard layout' unless map

          map
        end

        private_class_method def self.keyboard_flags(opts = {})
          pacing = opts.fetch(:pacing, 0).to_s
          raise ArgumentError, 'pacing must be 0, 20, 40 or 60 milliseconds' unless %w[0 20 40 60].include?(pacing)

          ext = 0x34
          ext |= 2 if opts[:serial_usb_visible]
          ext |= 8 if opts[:use_numeric_keypad]
          { ext: ext, tkt: opts[:no_enter] || opts[:enter] == false ? 0 : 0x20, cfg: (pacing.to_i / 20) << 2 }
        end

        private_class_method def self.parse_arguments(opts = {})
          parsed = Protocol.parse_args(args: opts[:args], flags: opts[:flags].map { |name| "--#{name}" }, values: opts[:values].map { |name| "--#{name}" })
          raise ArgumentError, 'OTP value options cannot be repeated' if parsed[:options].values.any?(Array)

          parsed
        end

        public_class_method def self.challenge_response(opts = {})
          challenge = opts[:challenge]
          slot = slot_number(slot: opts.fetch(:slot, 2))
          raise ArgumentError, 'challenge must be a raw String of 1 to 64 bytes' unless challenge.is_a?(String) && challenge.bytesize.between?(1, 64)

          Protocol.require_confirm(opts) if opts.key?(:confirm)
          state = status(opts)
          require_version(version: state[:version], minimum: [2, 2, 0])
          raise CommandError, 'OTP slot is empty' unless state[:slots][slot][:configured]

          padding = challenge.end_with?("\0") ? "\1" : "\0"
          response = transfer(opts.merge(command: slot == 1 ? 0x30 : 0x38, data: challenge.b.ljust(64, padding), response_length: 20))
          raise ResponseError, 'OTP response must contain exactly 20 raw bytes' unless response.is_a?(String) && response.bytesize == 20

          response.b
        end

        public_class_method def self.provision_challenge_response(opts = {})
          slot = slot_number(slot: opts.fetch(:slot, 2))
          consent(opts.merge(confirm: opts[:confirm]))
          validate_hmac_transport(connection: opts[:connection])
          key = obtain_secret(opts.merge(name: :key, value: opts[:key], length: 20))
          key = decode_secret(key: key, encoding: opts.fetch(:key_encoding, opts[:totp] && !opts[:generate] ? :base32 : :raw))
          key = OpenSSL::Digest::SHA1.digest(key) if key.bytesize > 64
          raise ArgumentError, 'HMAC key must contain 1 to 20 bytes, or more than 64 bytes' unless key.bytesize.between?(1, 20)

          challenge = opts.fetch(:verification_challenge) { SecureRandom.random_bytes(32) }
          raise ArgumentError, 'verification_challenge must contain 1 to 64 raw bytes' unless challenge.is_a?(String) && challenge.bytesize.between?(1, 64)
          raise ArgumentError, 'touch must be true or false' unless [true, false].include?(opts.fetch(:touch, true))

          access = access_codes(opts)
          config = pack_config(fixed: ''.b, uid: key.byteslice(16..).to_s.b.ljust(6, "\0"), key: key.byteslice(0, 16).ljust(16, "\0"), access_code: access[:new], ext: 0x24, tkt: 0x40, cfg: opts.fetch(:touch, true) ? 0x2e : 0x26)
          before = status(opts)
          require_version(version: before[:version], minimum: [2, 2, 0])
          result = write_verified(opts.merge(slot: slot, command: slot == 1 ? 1 : 3, data: config + access[:current], before: before, configured: true))
          begin
            response = challenge_response(opts.merge(slot: slot, challenge: challenge))
            expected = OpenSSL::HMAC.digest('SHA1', key, challenge)
            raise ResponseError, 'HMAC readback mismatch' unless OpenSSL.fixed_length_secure_compare(response, expected)
          rescue StandardError
            raise ResponseError, 'OTP provisioning state uncertain: HMAC readback failed; do not automatically reprogram', cause: nil
          end
          opts[:details] ? result.merge(verified: true, verification: :hmac_sha1) : :verified
        end

        private_class_method def self.write_verified(opts = {})
          before = opts[:before]
          transfer(opts)
          after = status(opts)
          sequence_ok = after[:programming_sequence] == before[:programming_sequence] + 1
          sequence_ok ||= after[:programming_sequence].zero? && before[:programming_sequence].positive? && after[:flags].nobits?(3)
          quirk = opts[:connection].descriptor[:protocol] == :apdu && (after[:version] <=> [5, 0, 0]) >= 0 && (after[:version] <=> [5, 4, 3]).negative? && after[:programming_sequence].zero? && before[:programming_sequence].positive?
          raise ResponseError, 'OTP programming readback is stale' unless before[:version] == after[:version] && (sequence_ok || quirk)
          raise ResponseError, 'OTP slot state readback mismatch' if opts.key?(:configured) && after[:slots][opts[:slot]][:configured] != opts[:configured]

          { slot: opts[:slot], status: after, verified: true, verification: sequence_ok ? :programming_sequence_and_slot_state : :firmware_quirk_slot_state, secret_readback: false }
        rescue StandardError
          raise ResponseError, 'OTP write state uncertain: acknowledgment or explicit readback failed; inspect the device, do not replay', cause: nil
        end

        private_class_method def self.pack_config(opts = {})
          fixed = opts[:fixed]
          body = fixed.ljust(16, "\0") + opts[:uid] + opts[:key] + opts[:access_code] + [fixed.bytesize, opts[:ext], opts[:tkt], opts[:cfg], 0, 0].pack('C*')
          raise ArgumentError, 'Invalid OTP configuration size' unless body.bytesize == 50

          crc = 0xffff
          body.each_byte do |byte|
            crc ^= byte
            8.times { crc = (crc >> 1) ^ (crc.odd? ? 0x8408 : 0) }
          end
          body + [(~crc) & 0xffff].pack('v')
        end

        private_class_method def self.secret_value(opts = {})
          value = opts[:value]
          value = opts[:secret_provider].call(opts[:name]) if value.nil? && opts[:secret_provider].respond_to?(:call)
          raise ArgumentError, "#{opts[:name]} must be supplied as nonempty in-memory bytes" unless value.is_a?(String) && !value.empty?

          value.b
        end

        private_class_method def self.access_codes(opts = {})
          current = opts[:access_code] || ("\0".b * 6)
          replacement = opts[:new_access_code] || current
          [current, replacement].each do |value|
            raise ArgumentError, 'OTP access codes must contain exactly six raw bytes' unless value.is_a?(String) && value.bytesize == 6
          end
          { current: current.b, new: replacement.b }
        end

        private_class_method def self.status(opts = {})
          raw = transfer(opts.merge(command: 0, data: ''.b, response_length: 6))
          raise ResponseError, 'Malformed OTP status' unless raw.is_a?(String) && raw.bytesize == 6

          version = raw.bytes.take(3)
          flags = raw.byteslice(4, 2).unpack1('v')
          configured = (version <=> [2, 1, 0]) >= 0
          touch = (version <=> [3, 0, 0]) >= 0
          {
            version: version, programming_sequence: raw.getbyte(3), flags: flags,
            slots: {
              1 => { configured: configured ? flags.anybits?(1) : nil, touch_triggered: touch ? flags.anybits?(4) : nil },
              2 => { configured: configured ? flags.anybits?(2) : nil, touch_triggered: touch ? flags.anybits?(8) : nil }
            }
          }
        end

        private_class_method def self.validate_hmac_transport(opts = {})
          connection = opts[:connection]
          raise ArgumentError, 'connection must implement descriptor and exchange' unless connection.respond_to?(:descriptor) && connection.respond_to?(:exchange)
          raise CommandError, 'HMAC over USB requires OTP HID; use NFC for smartcard challenge-response' if connection.descriptor[:protocol] == :apdu && connection.descriptor[:transport] == :usb

          :supported
        end

        private_class_method def self.validate_nfc(opts = {})
          descriptor = opts[:connection].descriptor
          return :supported if descriptor[:nfc] == true || descriptor[:transport] == :nfc
          raise CommandError, 'NFC is not supported on this device' if descriptor[:nfc] == false

          information = Management.info(connection: opts[:connection], timeout: opts.fetch(:timeout, 30))
          raise CommandError, 'NFC support is not reported by this device; do not assume every model supports NFC' unless information[:supported_capabilities].key?(:nfc)

          :supported
        end

        private_class_method def self.transfer(opts = {})
          connection = opts[:connection]
          raise ArgumentError, 'connection must implement exchange and descriptor' unless connection.respond_to?(:exchange) && connection.respond_to?(:descriptor)

          timeout = opts.fetch(:timeout, 30)
          raise ArgumentError, 'timeout must be finite positive seconds' unless timeout.is_a?(Numeric) && timeout.finite? && timeout.positive?

          case connection.descriptor[:protocol]
          when :otp
            connection.exchange(protocol: :otp, command: opts[:command], data: opts[:data], response_length: opts[:response_length], timeout: timeout)
          when :apdu
            if opts[:command].zero?
              Protocol.select(connection: connection, aid: AID, timeout: timeout)
            else
              raise CommandError, 'HMAC challenge-response over USB requires OTP HID; smartcard HMAC is NFC-only' if [0x30, 0x38].include?(opts[:command]) && connection.descriptor[:transport] == :usb

              Protocol.apdu(connection: connection, ins: 1, p1: opts[:command], data: opts[:data], timeout: timeout)
            end
          else
            raise ArgumentError, 'OTP requires OTP HID or smartcard/NFC transport'
          end
        end

        private_class_method def self.slot_number(opts = {})
          slot = opts[:slot]
          raise ArgumentError, 'slot must be integer 1 or 2' unless slot.is_a?(Integer) && [1, 2].include?(slot)

          slot
        end

        private_class_method def self.require_version(opts = {})
          raise CommandError, 'Operation not supported by this OTP firmware version' unless (opts[:version] <=> opts[:minimum]) >= 0

          :supported
        end

        private_class_method def self.consent(opts = {})
          raise ConfirmationRequired, 'This OTP operation requires confirm: true' unless opts[:confirm] == true

          %i[generate generate_key generate_private_id enter no_enter serial_public_id upload delete_access_code serial_usb_visible use_numeric_keypad touch totp force].each do |key|
            raise ArgumentError, "#{key} must be true or false" if opts.key?(key) && ![true, false].include?(opts[key])
          end

          :confirmed
        end

        public_class_method def self.authors(opts = {})
          opts[:format]
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help(opts = {})
          opts[:format]
          puts <<~HELP
            Native Ruby only. No subprocess backend. Never log binary responses or secrets.
            Writes are sent once. Uncertain readback raises; inspect rather than replay.
            OTP keyboard/NDEF settings cannot export stored secrets; verification scope is explicit.
            # List implemented OTP leaf operations without opening a device.
            #{self}.operations(
              format: 'optional - reserved output format'
            )
            # Dispatch one native OTP operation using nonsecret arguments only.
            #{self}.execute(
              args: 'optional - Array after otp, empty returns local metadata; credentials belong in memory',
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              access_code: 'optional - current six-byte raw slot access code; absence means no supplied access credential',
              new_access_code: 'optional - replacement six-byte raw access code; defaults to preserving the supplied current code',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them'
            )
            # Read firmware and slot configuration state without authentication.
            #{self}.info(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds'
            )
            # Delete the selected slot and verify its empty state.
            #{self}.delete_slot(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              access_code: 'optional - current six-byte raw slot access code; absence means no supplied access credential',
              new_access_code: 'optional - replacement six-byte raw access code; defaults to preserving the supplied current code',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              slot: 'required - integer slot 1 or 2'
            )
            # Swap both slot configurations and verify fresh slot state.
            #{self}.swap(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              access_code: 'optional - current six-byte raw slot access code; absence means no supplied access credential',
              new_access_code: 'optional - replacement six-byte raw access code; defaults to preserving the supplied current code',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them'
            )
            # Update keyboard and access settings without replacing the stored key.
            #{self}.settings(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              access_code: 'optional - current six-byte raw slot access code; absence means no supplied access credential',
              new_access_code: 'optional - replacement six-byte raw access code; defaults to preserving the supplied current code',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              slot: 'required - integer slot 1 or 2',
              delete_access_code: 'optional - true clears protection using the supplied current access code',
              enter: 'optional - append Enter by default; false disables it',
              no_enter: 'optional - true disables appended Enter',
              pacing: 'optional - 0, 20, 40 or 60 milliseconds between emitted keys',
              use_numeric_keypad: 'optional - true selects numeric keypad scan codes',
              serial_usb_visible: 'optional - true exposes serial through the USB descriptor'
            )
            # Provision YubiOTP with in-memory AES material and fresh status readback.
            #{self}.provision_yubiotp(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              access_code: 'optional - current six-byte raw slot access code; absence means no supplied access credential',
              new_access_code: 'optional - replacement six-byte raw access code; defaults to preserving the supplied current code',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              slot: 'required - integer slot 1 or 2',
              public_id: 'optional - lowercase even-length modhex public prefix up to 32 characters',
              serial_public_id: 'optional - true derives the prefix from the actual device serial',
              private_id: 'optional - required six raw bytes unless provider or explicit generation supplies them',
              key: 'optional - required sixteen raw AES key bytes unless provider or generation supplies them',
              generate_private_id: 'optional - true generates six private bytes and requires secret_sink',
              generate_key: 'optional - true generates sixteen AES key bytes and requires secret_sink',
              enter: 'optional - append Enter by default',
              no_enter: 'optional - true suppresses appended Enter',
              config_output: 'optional - explicit owned private CSV path; append only after verified programming, no symlinks',
              upload: 'optional - retired upstream flag; true raises before programming and never sends network data'
            )
            # Provision static password scan codes for the selected keyboard layout.
            #{self}.provision_static(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              access_code: 'optional - current six-byte raw slot access code; absence means no supplied access credential',
              new_access_code: 'optional - replacement six-byte raw access code; defaults to preserving the supplied current code',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              slot: 'required - integer slot 1 or 2',
              password: 'optional - required in-memory String of 1 to 38 supported characters unless generated or supplied by provider',
              keyboard_layout: 'optional - MODHEX default, US, UK, DE, FR, IT, BEPO or NORMAN',
              length: 'optional - generated password length from 1 through 38, defaults to 38',
              generate: 'optional - true generates a password and requires secret_sink',
              enter: 'optional - append Enter by default',
              no_enter: 'optional - true suppresses appended Enter'
            )
            # Provision a keyboard HOTP credential with explicit counter placement.
            #{self}.provision_hotp(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              access_code: 'optional - current six-byte raw slot access code; absence means no supplied access credential',
              new_access_code: 'optional - replacement six-byte raw access code; defaults to preserving the supplied current code',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              slot: 'required - integer slot 1 or 2',
              key: 'optional - required raw HMAC key unless provided in memory by secret_provider',
              digits: 'optional - 6 or 8 decimal output digits, defaults to 6',
              counter: 'optional - initial counter 0 through 1048560, divisible by 16',
              identifier: 'optional - 4, 8 or 12-character modhex/BCD token identifier; omitted means no prefix',
              enter: 'optional - append Enter by default',
              no_enter: 'optional - true suppresses appended Enter'
            )
            # Configure an NFC OTP URI or text record on a supported device.
            #{self}.configure_ndef(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              access_code: 'optional - current six-byte raw slot access code; absence means no supplied access credential',
              new_access_code: 'optional - replacement six-byte raw access code; defaults to preserving the supplied current code',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              slot: 'required - integer slot 1 or 2 with an existing credential',
              prefix: 'optional - UTF8 URI or text prefix; URI defaults to the Yubico URL',
              ndef_type: 'optional - URI default or TEXT; complete encoded prefix must fit 54 bytes'
            )
            # Calculate raw challenge bytes or an explicitly requested TOTP code.
            #{self}.calculate(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              access_code: 'optional - current six-byte raw slot access code; absence means no supplied access credential',
              new_access_code: 'optional - replacement six-byte raw access code; defaults to preserving the supplied current code',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              slot: 'optional - integer slot 1 or 2, defaults to 2',
              challenge: 'optional - raw 1 to 64-byte input for non-TOTP calculations',
              challenge_argument: 'optional - nonsecret hexadecimal input, or decimal timestamp when totp is true',
              totp: 'optional - true returns a decimal code rather than raw bytes',
              timestamp: 'optional - explicit nonnegative Unix seconds for TOTP, defaults to current time',
              digits: 'optional - 6 or 8 TOTP digits, defaults to 6'
            )
            # Calculate raw HMAC-SHA1 through an already provisioned OTP slot.
            #{self}.challenge_response(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              access_code: 'optional - current six-byte raw slot access code; absence means no supplied access credential',
              new_access_code: 'optional - replacement six-byte raw access code; defaults to preserving the supplied current code',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              challenge: 'required - raw binary String of 1 through 64 bytes; return is exactly 20 raw bytes',
              slot: 'optional - integer slot 1 or 2, defaults to 2'
            )
            # Provision HMAC-SHA1 and verify a fresh challenge using native cryptography.
            #{self}.provision_challenge_response(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              access_code: 'optional - current six-byte raw slot access code; absence means no supplied access credential',
              new_access_code: 'optional - replacement six-byte raw access code; defaults to preserving the supplied current code',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              slot: 'optional - integer slot 1 or 2, defaults to 2',
              key: 'optional - required raw HMAC material unless provider or explicit generation supplies it',
              key_encoding: 'optional - raw default, hex or base32; never guessed',
              totp: 'optional - true decodes a supplied Base32 key unless key_encoding overrides it',
              generate: 'optional - true generates a 20-byte key and requires secret_sink',
              touch: 'optional - true by default in this typed API; execute chalresp defaults false unless --touch',
              verification_challenge: 'optional - explicit raw 1 to 64-byte test challenge; defaults to 32 random bytes',
              details: 'optional - true returns verification metadata; default returns the legacy verified Symbol'
            )
            # Return module author information.
            #{self}.authors(
              format: 'optional - reserved output format'
            )
          HELP
          nil
        end
      end
    end
  end
end
