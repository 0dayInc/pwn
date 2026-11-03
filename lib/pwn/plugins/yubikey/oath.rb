# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'base64'
require 'uri'
require 'rexml/document'
require 'rexml/xpath'

module PWN
  module Plugins
    module YubiKey
      # Native OATH application protocol. Wire reference: yubikey-manager 5.9.1
      # yubikit/oath.py; https://developers.yubico.com/OATH/YKOATH_Protocol.html
      # Independently implemented Ruby; no external command or credential storage.
      module OATH
        AID = ['a0000005272101'].pack('H*').freeze
        ALGORITHMS = { sha1: 1, sha256: 2, sha512: 3 }.freeze
        TYPES = { hotp: 0x10, totp: 0x20 }.freeze
        PSKC_NS = { 'p' => 'urn:ietf:params:xml:ns:keyprov:pskc', 'x' => 'http://www.w3.org/2001/04/xmlenc#',
                    'd' => 'http://www.w3.org/2000/09/xmldsig#', 'x11' => 'http://www.w3.org/2009/xmlenc11#' }.freeze

        public_class_method def self.execute(opts = {})
          args = opts.fetch(:args, [])
          raise ArgumentError, 'args must be an Array of Strings' unless args.is_a?(Array) && args.all?(String)
          return { application: :oath, operations: operations } if args.empty? || [%w[accounts], %w[access]].include?(args)

          count = %w[accounts access].include?(args.first) ? 2 : 1
          operation = args.first(count).join(' ')
          raise ArgumentError, 'Unknown OATH operation' unless operations.include?(operation)

          grammar = {
            'info' => [0, [], []], 'reset' => [0, %w[--force], []],
            'access change' => [0, %w[--clear --remember], []], 'access remember' => [0, [], []], 'access forget' => [0, %w[--all], []],
            'accounts list' => [0, %w[--show-hidden --oath-type --period --remember], []],
            'accounts code' => [0..1, %w[--show-hidden --single --remember], []],
            'accounts add' => [1, %w[--touch --force --generate --remember], %w[--oath-type --algorithm --digits --period --counter --issuer]],
            'accounts uri' => [0, %w[--touch --force --remember], []],
            'accounts import' => [0, %w[--touch --force --remember], []],
            'accounts rename' => [2, %w[--force --remember], []], 'accounts delete' => [1, %w[--force --remember], []]
          }.fetch(operation)
          parsed = Protocol.parse_args(args: args.drop(count), flags: grammar[1], values: grammar[2])
          positional = parsed[:positionals]
          raise ArgumentError, 'Unexpected OATH positional arguments' unless Array(grammar[0]).include?(positional.length)

          options = opts.merge(parsed[:options])
          %i[generate touch clear all remember use_cache force overwrite].each do |control|
            raise ArgumentError, "#{control} must be a boolean" if options.key?(control) && ![true, false].include?(options[control])
          end
          case operation
          when 'reset' then return reset(options)
          when 'access change' then return change_access(options)
          when 'access remember', 'access forget' then return cache_access(options.merge(operation: operation))
          when 'accounts code'
            raise ArgumentError, 'single requires one exact account identity' if options[:single] && positional.empty?

            return positional.empty? ? calculate_all(options) : code(options.merge(account: positional.first))
          when 'accounts add' then return put(options.merge(name: positional.first))
          when 'accounts import' then return import_credentials(options)
          when 'accounts uri'
            Protocol.require_confirm(options)
            uri = Protocol.secret(value: opts[:uri], secret_provider: opts[:secret_provider], name: :uri)
            parsed_uri = parse_uri(uri: uri)
            return put(options.merge(parsed_uri).merge(touch: options.fetch(:touch, false)))
          when 'accounts rename', 'accounts delete'
            return modify(options.merge(operation: operation, account: positional[0], new_name: positional[1]))
          end
          session = session(options)
          return { version: session[:version], device_id: session[:device_id], locked: !session[:challenge].nil? } if operation == 'info'

          unlock(options.merge(session: session))
          list(session: session)
        end

        public_class_method def self.operations
          ['info', 'reset', 'access change', 'access remember', 'access forget',
           'accounts list', 'accounts code', 'accounts add', 'accounts uri', 'accounts import', 'accounts rename', 'accounts delete']
        end

        public_class_method def self.parse_uri(opts = {})
          text = opts[:uri]
          raise ArgumentError, 'uri must be a bounded otpauth URI' unless text.is_a?(String) && text.bytesize <= 8192 && !text.match?(/%(?![0-9a-fA-F]{2})/)

          uri = URI.parse(text)
          raise ArgumentError, 'Invalid otpauth URI' unless uri.scheme == 'otpauth' && %w[totp hotp].include?(uri.host) && uri.userinfo.nil? && uri.port.nil? && uri.fragment.nil? && uri.path.start_with?('/')

          pairs = URI.decode_www_form(uri.query.to_s)
          raise ArgumentError, 'Duplicate or unknown otpauth parameters' unless pairs.map(&:first).uniq.length == pairs.length && (pairs.map(&:first) - %w[secret issuer algorithm digits period counter]).empty?

          fields = pairs.to_h
          label = URI::DEFAULT_PARSER.unescape(uri.path.byteslice(1..)).force_encoding(Encoding::UTF_8)
          raise ArgumentError, 'Invalid UTF-8 otpauth identity' unless label.valid_encoding?

          issuer, name = label.include?(':') ? label.split(':', 2) : [nil, label]
          raise ArgumentError, 'Conflicting otpauth issuer identities' if issuer && fields['issuer'] && issuer != fields['issuer']
          raise ArgumentError, 'HOTP URI requires a counter' if uri.host == 'hotp' && !fields.key?('counter')

          data = credential_data(name: name, issuer: fields.fetch('issuer', issuer), oath_type: uri.host, algorithm: fields.fetch('algorithm', 'SHA1'),
                                 digits: fields.fetch('digits', 6), period: fields.fetch('period', 30), counter: fields.fetch('counter', 0))
          data.merge(secret: decode_base32(value: fields['secret']))
        rescue URI::InvalidURIError
          raise ArgumentError, 'Invalid otpauth URI', cause: nil
        end

        private_class_method def self.integer(opts = {})
          value = opts[:value]
          value = Integer(value, 10) if value.is_a?(String) && value.match?(/\A[0-9]+\z/)
          raise ArgumentError, 'Invalid numeric OATH option' unless value.is_a?(Integer) && opts.fetch(:range).cover?(value)

          value
        end

        private_class_method def self.credential_data(opts = {})
          name = identity(value: opts[:name])
          issuer = opts[:issuer]
          raise ArgumentError, 'issuer must be an exact nonempty String without colon' if issuer && (!issuer.is_a?(String) || issuer.empty? || issuer.include?(':'))

          type = opts.fetch(:oath_type, :totp).to_s.downcase.to_sym
          algorithm = opts.fetch(:algorithm, :sha1).to_s.downcase.to_sym
          raise ArgumentError, 'Unknown OATH type or hash algorithm' unless TYPES.key?(type) && ALGORITHMS.key?(algorithm)

          digits = integer(value: opts.fetch(:digits, 6), range: 6..8)
          period = integer(value: opts.fetch(:period, 30), range: 1..0x7fffffff)
          counter = integer(value: opts.fetch(:counter, 0), range: 0..0xffffffff)
          raise ArgumentError, 'Initial counter is only valid for HOTP' if type != :hotp && counter.positive?
          raise ArgumentError, 'touch must be a boolean' if opts.key?(:touch) && ![true, false].include?(opts[:touch])

          id = (type == :totp && period != 30 ? "#{period}/".b : ''.b) + (issuer ? "#{issuer}:".b : ''.b) + name
          identity(value: id)
          { id: id, name: name, issuer: issuer, oath_type: type, algorithm: algorithm, digits: digits, period: period, counter: counter, touch: opts.fetch(:touch, false) }
        end

        private_class_method def self.decode_base32(opts = {})
          value = opts[:value]
          raise ArgumentError, 'secret_base32 must be canonical Base32' unless value.is_a?(String) && value.bytesize.between?(2, 8192) && value.match?(/\A[A-Za-z2-7]+={0,6}\z/)

          raw = value.delete_suffix('=' * value.count('='))
          padding = value.bytesize - raw.bytesize
          raise ArgumentError, 'Invalid Base32 length or padding' unless [0, 2, 4, 5, 7].include?(raw.bytesize % 8) && (padding.zero? || ((value.bytesize % 8).zero? && padding == (8 - (raw.bytesize % 8)) % 8))

          alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
          bits = raw.upcase.chars.map { |char| alphabet.index(char).to_s(2).rjust(5, '0') }.join
          remainder = bits.bytesize % 8
          raise ArgumentError, 'Noncanonical Base32 padding bits' if remainder.positive? && bits.byteslice(-remainder, remainder).include?('1')

          [bits.byteslice(0, bits.bytesize - remainder)].pack('B*')
        end

        private_class_method def self.put(opts = {})
          data = credential_data(opts)
          raise ArgumentError, 'generate conflicts with a supplied secret' if opts[:generate] && (opts[:secret] || opts[:secret_base32])
          raise ArgumentError, 'Use either secret or secret_base32' if opts[:secret] && opts[:secret_base32]

          Protocol.require_confirm(opts)
          secret = if opts[:generate]
                     SecureRandom.random_bytes(20)
                   elsif opts[:secret_base32]
                     decode_base32(value: opts[:secret_base32])
                   else
                     Protocol.secret(value: opts[:secret], secret_provider: opts[:secret_provider], name: :secret)
                   end
          raise ArgumentError, 'OATH secret must contain 2 to 4096 raw bytes' unless secret.is_a?(String) && secret.bytesize.between?(2, 4096)

          session = session(opts)
          require_version(session: session, minimum: [4, 2, 6]) if data[:touch]
          require_version(session: session, minimum: [4, 3, 1]) if data[:algorithm] == :sha512
          unlock(opts.merge(session: session))
          existing = list(session: session)
          raise ArgumentError, 'Account already exists; explicit overwrite: true is required' if existing.any? { |entry| entry[:id] == data[:id] } && opts[:overwrite] != true && opts[:force] != true
          raise Error, 'Firmware prefix-overwrite defect; choose another exact account ID' if (session[:version] <=> [4, 0, 0]).positive? && (session[:version] <=> [4, 3, 5]).negative? && existing.any? { |entry| entry[:id] != data[:id] && entry[:id].start_with?(data[:id]) }

          store_credential(opts.merge(session: session, data: data, secret: secret))
        end

        private_class_method def self.store_credential(opts = {})
          session = opts.fetch(:session)
          data = opts.fetch(:data)
          secret = opts.fetch(:secret)
          digest = OpenSSL::Digest.new(data[:algorithm].to_s)
          encoded = secret.bytesize > digest.block_length ? digest.digest(secret) : secret.b
          encoded = encoded.ljust(14, "\x00")
          payload = tlv(tag: 0x71, value: data[:id]) + tlv(tag: 0x73, value: [TYPES.fetch(data[:oath_type]) | ALGORITHMS.fetch(data[:algorithm]), data[:digits]].pack('CC') + encoded)
          payload += "\x78\x02".b if data[:touch] # This property is a tag/value pair, NOT BER-TLV.
          payload += tlv(tag: 0x7a, value: [data[:counter]].pack('N')) if data[:counter].positive?
          send_apdu(session: session, ins: 1, data: payload)
          found = list(session: session).find { |entry| entry[:id] == data[:id] }
          raise ResponseError, 'OATH import acknowledged but LIST readback did not match' unless found && found[:oath_type] == data[:oath_type] && found[:algorithm] == data[:algorithm]

          result = found.merge(verified: true, verification: :identity_and_algorithm)
          result[:generated_secret] = secret if opts[:generate]
          result
        end

        private_class_method def self.import_credentials(opts = {})
          raise ArgumentError, 'Choose credentials or pskc, not both' if opts[:credentials] && opts[:pskc]

          Protocol.require_confirm(opts)
          records = opts[:credentials] || parse_pskc(opts)
          raise ArgumentError, 'Import requires 1 to 256 credential records' unless records.is_a?(Array) && records.length.between?(1, 256)

          prepared = records.map do |record|
            allowed = %i[name issuer oath_type algorithm digits period counter touch secret secret_base32]
            raise ArgumentError, 'Invalid credential import record' unless record.is_a?(Hash) && (record.keys - allowed).empty?

            data = credential_data(record.merge(touch: opts.fetch(:touch, record.fetch(:touch, false))))
            raise ArgumentError, 'Choose one secret encoding per record' if record[:secret] && record[:secret_base32]

            secret = record[:secret_base32] ? decode_base32(value: record[:secret_base32]) : record[:secret]
            raise ArgumentError, 'Each OATH secret must contain 2 to 4096 raw bytes' unless secret.is_a?(String) && secret.bytesize.between?(2, 4096)

            { data: data, secret: secret }
          end
          ids = prepared.map { |record| record[:data][:id] }
          raise ArgumentError, 'Duplicate account identities in import' unless ids.uniq.length == ids.length

          session = session(opts)
          prepared.each do |record|
            require_version(session: session, minimum: [4, 2, 6]) if record[:data][:touch]
            require_version(session: session, minimum: [4, 3, 1]) if record[:data][:algorithm] == :sha512
          end
          unlock(opts.merge(session: session))
          existing = list(session: session).map { |entry| entry[:id] }
          raise ArgumentError, 'Import would overwrite an account; explicit overwrite: true is required' if ids.intersect?(existing) && opts[:overwrite] != true && opts[:force] != true
          raise Error, 'Firmware prefix-overwrite defect prevents this import' if (session[:version] <=> [4, 0, 0]).positive? && (session[:version] <=> [4, 3, 5]).negative? && ids.any? { |id| (ids + existing).any? { |other| other != id && other.start_with?(id) } }

          prepared.map { |record| store_credential(record.merge(session: session)) }
        end

        private_class_method def self.xml_node(opts = {})
          matches = REXML::XPath.match(opts.fetch(:node), opts.fetch(:path), PSKC_NS)
          raise ArgumentError, 'Ambiguous duplicate PSKC field' if matches.length > 1

          matches.first
        end

        private_class_method def self.xml_text(opts = {})
          xml_node(opts)&.text
        end

        private_class_method def self.parse_pskc(opts = {})
          xml = opts[:pskc]
          xml = Protocol.secret(secret_provider: opts[:secret_provider], name: :pskc) if xml.nil?
          raise ArgumentError, 'pskc must be in-memory XML, at most one MiB, with no DTD/entities' unless xml.is_a?(String) && xml.bytesize <= 1_048_576 && !xml.match?(/<!DOCTYPE|<!ENTITY/i)

          document = REXML::Document.new(xml)
          root = document.root
          raise ArgumentError, 'Expected a PSKC 1.0 KeyContainer' unless root && root.name == 'KeyContainer' && root.namespace == PSKC_NS['p'] && root.attributes['Version'] == '1.0'
          raise ArgumentError, 'Signed PSKC containers require caller-side signature verification before import' if xml_node(node: root, path: 'd:Signature')

          opts = opts.merge(crypto: pskc_crypto(opts.merge(root: root))) if REXML::XPath.match(root, './/p:EncryptedValue', PSKC_NS).any?

          nodes = REXML::XPath.match(root, 'p:KeyPackage/p:Key', PSKC_NS)
          raise ArgumentError, 'PSKC must contain 1 to 256 credentials' unless nodes.length.between?(1, 256)

          nodes.map do |node|
            type = node.attributes['Algorithm']
            raise ArgumentError, 'Unsupported PSKC credential algorithm' unless ["#{PSKC_NS['p']}:totp", "#{PSKC_NS['p']}:hotp"].include?(type)

            name = node.attributes['Id']
            issuer = xml_text(node: node, path: 'p:Issuer')
            friendly = xml_text(node: node, path: 'p:FriendlyName')
            if friendly&.include?(':')
              friendly_issuer, name = friendly.split(':', 2)
              issuer ||= friendly_issuer
            end
            user = xml_text(node: node, path: 'p:UserId')
            if user
              name = user
              if user.start_with?('CN=')
                begin
                  dn = OpenSSL::X509::Name.parse_rfc2253(user)
                  name = dn.to_a.find { |field| field[0] == 'CN' }&.[](1) || user
                rescue OpenSSL::X509::NameError
                  raise ArgumentError, 'Malformed PSKC UserId distinguished name', cause: nil
                end
              end
            end
            response = xml_node(node: node, path: 'p:AlgorithmParameters/p:ResponseFormat')
            raise ArgumentError, 'Only decimal OATH response format is supported' if response && response.attributes['Encoding'] != 'DECIMAL'

            secret_node = xml_node(node: node, path: 'p:Data/p:Secret')
            raise ArgumentError, 'Missing PSKC secret' unless secret_node

            secret = pskc_value(opts.merge(node: secret_node, binary: true))
            { name: name, issuer: issuer, oath_type: type.split(':').last, secret: secret,
              algorithm: xml_text(node: node, path: 'p:AlgorithmParameters/p:Suite') || 'SHA1', digits: response&.attributes&.[]('Length') || 6,
              period: pskc_number(opts.merge(node: node, field: 'TimeInterval', default: 30)), counter: pskc_number(opts.merge(node: node, field: 'Counter', default: 0)) }
          end
        rescue REXML::ParseException
          raise ArgumentError, 'Malformed PSKC XML', cause: nil
        end

        private_class_method def self.pskc_number(opts = {})
          node = xml_node(node: opts.fetch(:node), path: "p:Data/p:#{opts.fetch(:field)}")
          node ? pskc_value(opts.merge(node: node, binary: false)) : opts.fetch(:default)
        end

        private_class_method def self.pskc_value(opts = {})
          node = opts.fetch(:node)
          plain = xml_node(node: node, path: 'p:PlainValue')
          encrypted = xml_node(node: node, path: 'p:EncryptedValue')
          raise ArgumentError, 'PSKC field must have exactly one value encoding' unless plain.nil? != encrypted.nil?
          return opts[:binary] ? Base64.strict_decode64(plain.text.to_s.gsub(/[\r\n\t ]/, '')) : plain.text if plain

          algorithm = xml_node(node: encrypted, path: 'x:EncryptionMethod')&.attributes&.[]('Algorithm')
          ciphertext = Base64.strict_decode64(xml_text(node: encrypted, path: 'x:CipherData/x:CipherValue').to_s.gsub(/[\r\n\t ]/, ''))
          crypto = opts.fetch(:crypto)
          mac = xml_text(node: node, path: 'p:ValueMAC')
          if mac || algorithm.to_s.end_with?('-cbc')
            raise ArgumentError, 'PSKC CBC requires authenticated ValueMAC' unless mac && crypto[:mac_key] && crypto[:mac_hash]

            expected = OpenSSL::HMAC.digest(crypto[:mac_hash], crypto[:mac_key], ciphertext)
            actual = Base64.strict_decode64(mac.gsub(/[\r\n\t ]/, ''))
            raise ArgumentError, 'PSKC integrity check failed; no credentials imported' unless actual.bytesize == expected.bytesize && OpenSSL.fixed_length_secure_compare(actual, expected)
          end
          value = pskc_decrypt(node: encrypted, key: crypto[:key])
          opts[:binary] ? value : value.bytes.reduce(0) { |total, byte| (total << 8) | byte }
        end

        private_class_method def self.pskc_crypto(opts = {})
          root = opts.fetch(:root)
          derivation = xml_node(node: root, path: 'p:EncryptionKey/x11:DerivedKey/x11:KeyDerivationMethod')
          if derivation
            raise ArgumentError, 'Unsupported PSKC key derivation method' unless derivation.attributes['Algorithm'] == "#{PSKC_NS['x11']}pbkdf2"
            raise ArgumentError, 'PSKC derivation conflicts with a supplied raw key' if opts[:pskc_key]

            params = xml_node(node: derivation, path: 'x11:PBKDF2-params')
            raise ArgumentError, 'Missing PSKC PBKDF2 parameters' unless params

            iterations = integer(value: xml_text(node: params, path: "*[local-name()='IterationCount']"), range: 1..1_000_000)
            length = integer(value: xml_text(node: params, path: "*[local-name()='KeyLength']"), range: 16..32)
            raise ArgumentError, 'Invalid PSKC AES key length' unless [16, 24, 32].include?(length)

            salt = Base64.strict_decode64(xml_text(node: params, path: "*[local-name()='Salt']/*[local-name()='Specified']").to_s.gsub(/[\r\n\t ]/, ''))
            raise ArgumentError, 'PSKC PBKDF2 salt must contain 1 to 1024 bytes' unless salt.bytesize.between?(1, 1024)

            prf = xml_node(node: params, path: "*[local-name()='PRF']")
            hash = pskc_hash(value: (prf && (prf.attributes['Algorithm'] || prf.text)) || "#{PSKC_NS['d']}hmac-sha1")
            password = Protocol.secret(value: opts[:pskc_password], secret_provider: opts[:secret_provider], name: :pskc_password)
            key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iterations, length, hash)
          else
            raise ArgumentError, 'PSKC has no password derivation parameters; supply pskc_key' if opts[:pskc_password]

            key = Protocol.secret(value: opts[:pskc_key], secret_provider: opts[:secret_provider], name: :pskc_key)
          end
          method = xml_node(node: root, path: 'p:MACMethod')
          return { key: key } unless method

          hash = pskc_hash(value: method.attributes['Algorithm'])
          encrypted = xml_node(node: method, path: 'p:MACKey')
          raise ArgumentError, 'Missing encrypted PSKC MACKey' unless encrypted

          { key: key, mac_key: pskc_decrypt(node: encrypted, key: key), mac_hash: hash }
        end

        private_class_method def self.pskc_hash(opts = {})
          names = { "#{PSKC_NS['d']}hmac-sha1" => 'SHA1', 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256' => 'SHA256',
                    'http://www.w3.org/2001/04/xmldsig-more#hmac-sha512' => 'SHA512' }
          names.fetch(opts[:value]) { raise ArgumentError, 'Unsupported PSKC HMAC algorithm' }
        end

        private_class_method def self.pskc_decrypt(opts = {})
          node = opts.fetch(:node)
          algorithm = xml_node(node: node, path: 'x:EncryptionMethod')&.attributes&.[]('Algorithm')
          match = algorithm&.match(%r{\Ahttp://www\.w3\.org/2001/04/xmlenc#(?:kw-aes(128|192|256)|aes(128|192|256)-cbc)\z})
          raise ArgumentError, 'Unsupported PSKC encryption algorithm' unless match

          bits = match[1] || match[2]
          key = opts.fetch(:key)
          raise ArgumentError, 'PSKC key has incorrect raw byte length' unless key.bytesize * 8 == Integer(bits, 10)

          ciphertext = Base64.strict_decode64(xml_text(node: node, path: 'x:CipherData/x:CipherValue').to_s.gsub(/[\r\n\t ]/, ''))
          cipher = OpenSSL::Cipher.new("aes-#{bits}-#{match[1] ? 'wrap' : 'cbc'}")
          cipher.decrypt
          cipher.key = key
          cipher.iv = match[1] ? "\xa6".b * 8 : ciphertext.slice!(0, 16)
          cipher.update(ciphertext) + cipher.final
        rescue OpenSSL::OpenSSLError
          raise ArgumentError, 'PSKC integrity/decryption failed; no credentials imported', cause: nil
        end

        private_class_method def self.require_version(opts = {})
          raise Error, 'OATH operation is unsupported by the selected application version' unless Protocol.version_at_least?(version: opts.fetch(:session)[:version], minimum: opts.fetch(:minimum))
        end

        private_class_method def self.modify(opts = {})
          id = identity(value: opts[:account])
          rename = opts[:operation] == 'accounts rename'
          new_name = identity(value: opts[:new_name]) if rename
          Protocol.require_confirm(opts)
          session = session(opts)
          require_version(session: session, minimum: [5, 3, 1]) if rename
          unlock(opts.merge(session: session))
          entries = list(session: session)
          found = entries.find { |entry| entry[:id] == id }
          raise ResponseError, 'No exact OATH account identifier' unless found

          payload = tlv(tag: 0x71, value: id)
          if rename
            new_id = (found[:oath_type] == :totp && found[:period] != 30 ? "#{found[:period]}/".b : ''.b) + new_name
            identity(value: new_id)
            raise ArgumentError, 'Target account already exists' if entries.any? { |entry| entry[:id] == new_id }

            send_apdu(session: session, ins: 5, data: payload + tlv(tag: 0x71, value: new_id))
            after = list(session: session)
            raise ResponseError, 'OATH rename readback failed' unless after.any? { |entry| entry[:id] == new_id } && after.none? { |entry| entry[:id] == id }

            { id: new_id, previous_id: id, verified: true }
          else
            send_apdu(session: session, ins: 2, data: payload)
            raise ResponseError, 'OATH delete readback failed' if list(session: session).any? { |entry| entry[:id] == id }

            { deleted: id, verified: true }
          end
        end

        public_class_method def self.code(opts = {})
          account = identity(value: opts[:account])
          timestamp = timestamp(value: opts[:timestamp])
          Protocol.require_confirm(opts)
          session = session(opts)
          unlock(opts.merge(session: session))
          matches = list(session: session).select { |credential| credential[:id] == account }
          raise ResponseError, 'OATH requires one exact account identifier' unless matches.length == 1

          code_record(session: session, credential: matches.first, timestamp: timestamp).fetch(:value)
        end

        public_class_method def self.calculate(opts = {})
          id = identity(value: opts[:account])
          challenge = opts[:challenge]
          raise ArgumentError, 'challenge must contain at most 64 raw bytes' unless challenge.is_a?(String) && challenge.bytesize <= 64

          Protocol.require_confirm(opts)
          session = session(opts)
          unlock(opts.merge(session: session))
          found = list(session: session).find { |entry| entry[:id] == id }
          raise ResponseError, 'No exact OATH account identifier' unless found

          response = send_apdu(session: session, ins: 0xa2, data: tlv(tag: 0x71, value: id) + tlv(tag: 0x74, value: challenge.b))
          value = Protocol.tlv_map(data: response)[0x75]
          length = OpenSSL::Digest.new(found[:algorithm].to_s).digest_length
          raise ResponseError, 'Malformed OATH HMAC response' unless value && value.bytesize == length + 1 && value.getbyte(0).between?(6, 8)

          value.byteslice(1..)
        end

        public_class_method def self.calculate_all(opts = {})
          timestamp = timestamp(value: opts[:timestamp])
          Protocol.require_confirm(opts)
          session = session(opts)
          unlock(opts.merge(session: session))
          response = send_apdu(session: session, ins: 0xa4, p2: 1, data: tlv(tag: 0x74, value: [timestamp / 30].pack('Q>')))
          fields = Protocol.untlv(data: response)
          raise ResponseError, 'Malformed OATH CALCULATE ALL pairs' if fields.length.odd?

          seen = []
          fields.each_slice(2).map do |name, answer|
            raise ResponseError, 'Malformed OATH CALCULATE ALL record' unless name[:tag] == 0x71 && [0x76, 0x77, 0x7c].include?(answer[:tag])
            raise ResponseError, 'Duplicate OATH calculation identity' if seen.include?(name[:value])

            seen << name[:value]
            item = credential(id: name[:value], type: answer[:tag] == 0x77 ? 0x10 : 0x20, algorithm: 1)
            item.delete(:algorithm) # CALCULATE ALL does not report the hash algorithm.
            code = if answer[:tag] == 0x76
                     item[:period] == 30 ? format_code(credential: item, timestamp: timestamp, truncated: answer[:value]) : code_record(session: session, credential: item, timestamp: timestamp)
                   end
            item.merge(touch: answer[:tag] == 0x7c, code: code)
          end
        end

        private_class_method def self.validate_access_options(opts = {})
          %i[remember use_cache].each do |control|
            raise ArgumentError, "#{control} must be a boolean" if opts.key?(control) && ![true, false].include?(opts[control])
          end
          raise ArgumentError, 'Choose password or access_key, not both' if opts[:password] && opts[:access_key]
          raise ArgumentError, 'use_cache conflicts with an explicit access credential' if opts[:use_cache] && (opts[:password] || opts[:access_key])
          raise ArgumentError, 'access_key must contain exactly 16 raw bytes' if opts[:access_key] && (!opts[:access_key].is_a?(String) || opts[:access_key].bytesize != 16)

          cache(opts) if opts[:remember] || opts[:use_cache]
        end

        private_class_method def self.cache(opts = {})
          value = opts[:encrypted_cache]
          required = opts.fetch(:methods, %i[fetch store delete])
          raise ArgumentError, 'Supply an explicit encrypted_cache adapter; no host cache is opened' unless value.respond_to?(:encrypted?) && value.encrypted? == true && required.all? { |method| value.respond_to?(method) }

          value
        end

        private_class_method def self.remember_key(opts = {})
          store = cache(opts)
          id = opts.fetch(:session)[:device_id]
          key = opts.fetch(:key)
          store.store(device_id: id, access_key: key.dup)
          readback = store.fetch(device_id: id)
          raise ResponseError, 'Encrypted cache handoff readback failed' unless readback.is_a?(String) && readback.bytesize == key.bytesize && OpenSSL.fixed_length_secure_compare(readback, key)

          { cache_handoff: true, verified: true }
        end

        private_class_method def self.cache_access(opts = {})
          all = opts[:all] == true
          raise ArgumentError, 'all is only valid for access forget' if all && opts[:operation] != 'access forget'

          store = cache(opts.merge(methods: all ? %i[clear empty?] : %i[fetch store delete]))
          Protocol.require_confirm(opts)
          if all
            store.clear
            raise ResponseError, 'Encrypted cache clear readback failed' unless store.empty?

            return { forgotten: :all, verified: true }
          end
          session = session(opts)
          if opts[:operation] == 'access remember'
            raise ArgumentError, 'Cannot remember an unprotected OATH application' unless session[:challenge]

            key = unlock(opts.merge(session: session, remember: false))
            remember_key(opts.merge(session: session, key: key))
          else
            store.delete(device_id: session[:device_id])
            raise ResponseError, 'Encrypted cache delete readback failed' unless store.fetch(device_id: session[:device_id]).nil?

            { forgotten: true, verified: true }
          end
        end

        private_class_method def self.change_access(opts = {})
          clear = opts[:clear] == true
          raise ArgumentError, 'clear conflicts with a new access credential or remember' if clear && (opts[:new_password] || opts[:new_access_key] || opts[:remember])
          raise ArgumentError, 'Choose new_password or new_access_key, not both' if opts[:new_password] && opts[:new_access_key]

          validate_access_options(opts)
          Protocol.require_confirm(opts)
          key = opts[:new_access_key]
          raise ArgumentError, 'new_access_key must contain exactly 16 raw bytes' if key && (!key.is_a?(String) || key.bytesize != 16)

          new_password = Protocol.secret(value: opts[:new_password], secret_provider: opts[:secret_provider], name: :new_password) unless clear || key
          session = session(opts)
          unlock(opts.merge(session: session, remember: false))
          if clear
            send_apdu(session: session, ins: 3, data: tlv(tag: 0x73, value: ''.b))
          else
            key ||= OpenSSL::PKCS5.pbkdf2_hmac(new_password, session[:salt], 1000, 16, 'SHA1')
            challenge = SecureRandom.random_bytes(8)
            payload = tlv(tag: 0x73, value: "\x21".b + key) + tlv(tag: 0x74, value: challenge) + tlv(tag: 0x75, value: OpenSSL::HMAC.digest('SHA1', key, challenge))
            send_apdu(session: session, ins: 3, data: payload)
          end
          fresh = session(opts)
          raise ResponseError, 'OATH access change SELECT readback failed' unless fresh[:salt] == session[:salt] && fresh[:challenge].nil? == clear

          result = { locked: !clear, verified: true, verification: :protection_state_only }
          result.merge!(remember_key(opts.merge(session: fresh, key: key))) if opts[:remember]
          result
        end

        private_class_method def self.reset(opts = {})
          Protocol.require_confirm(opts)
          before = session(opts)
          send_apdu(session: before, ins: 4, p1: 0xde, p2: 0xad)
          after = session(opts)
          raise ResponseError, 'OATH reset readback failed' unless after[:challenge].nil? && before[:salt] != after[:salt] && list(session: after).empty?

          { reset: true, verified: true, device_id: after[:device_id] }
        end

        private_class_method def self.session(opts = {})
          validate_access_options(opts)
          connection = opts[:connection]
          raise ArgumentError, 'OATH requires an APDU connection' unless connection.respond_to?(:exchange) && connection.respond_to?(:descriptor) && connection.descriptor[:protocol] == :apdu

          timeout = opts.fetch(:timeout, 30)
          raise ArgumentError, 'timeout must be finite and positive' unless timeout.is_a?(Numeric) && timeout.finite? && timeout.positive?

          selected = Protocol.select(connection: connection, aid: AID, timeout: timeout, get_response_ins: 0xa5, get_response_le: 0)
          fields = Protocol.tlv_map(data: selected)
          version = fields[0x79]
          salt = fields[0x71]
          challenge = fields[0x74]
          raise ResponseError, 'Malformed OATH SELECT response' unless version&.bytesize == 3 && salt && !salt.empty? && (challenge.nil? || challenge.bytesize == 8)

          { connection: connection, timeout: timeout, version: version.bytes, salt: salt, challenge: challenge,
            device_id: Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(salt)[0, 16]).delete('=') }
        end

        private_class_method def self.send_apdu(opts = {})
          session = opts.fetch(:session)
          Protocol.apdu(connection: session[:connection], timeout: session[:timeout], ins: opts.fetch(:ins), p1: opts.fetch(:p1, 0), p2: opts.fetch(:p2, 0), data: opts.fetch(:data, ''.b), get_response_ins: 0xa5, get_response_le: 0)
        end

        private_class_method def self.unlock(opts = {})
          session = opts.fetch(:session)
          unless session[:challenge]
            raise ArgumentError, 'OATH application has no access key; supplied authentication is not applicable' if opts[:password] || opts[:access_key] || opts[:remember] || opts[:use_cache]

            return
          end

          Protocol.require_confirm(opts)
          key = opts[:access_key]
          key = cache(opts).fetch(device_id: session[:device_id]) if opts[:use_cache]
          raise ArgumentError, 'No explicit cached key for this OATH application' if opts[:use_cache] && key.nil?

          if key.nil?
            password = Protocol.secret(value: opts[:password], secret_provider: opts[:secret_provider], name: :password)
            key = OpenSSL::PKCS5.pbkdf2_hmac(password, session[:salt], 1000, 16, 'SHA1')
          end
          raise ArgumentError, 'access_key must contain exactly 16 raw bytes' unless key.is_a?(String) && key.bytesize == 16

          challenge = SecureRandom.random_bytes(8)
          answer = OpenSSL::HMAC.digest('SHA1', key, session[:challenge])
          response = send_apdu(session: session, ins: 0xa3, data: tlv(tag: 0x75, value: answer) + tlv(tag: 0x74, value: challenge))
          fields = Protocol.tlv_map(data: response)
          expected = OpenSSL::HMAC.digest('SHA1', key, challenge)
          actual = fields[0x75]
          raise ResponseError, 'OATH mutual authentication failed' unless actual&.bytesize == expected.bytesize && OpenSSL.fixed_length_secure_compare(actual, expected)

          session[:challenge] = nil
          remember_key(opts.merge(key: key)) if opts[:remember]
          key
        end

        private_class_method def self.tlv(opts = {})
          Protocol.tlv(tag: opts.fetch(:tag), value: opts.fetch(:value))
        end

        private_class_method def self.identity(opts = {})
          value = opts[:value]
          raise ArgumentError, 'account must contain 1 to 64 exact bytes' unless value.is_a?(String) && value.bytesize.between?(1, 64)

          value.b
        end

        private_class_method def self.timestamp(opts = {})
          value = opts.fetch(:value, nil)
          value = Time.now.to_i if value.nil?
          raise ArgumentError, 'timestamp must be a nonnegative Integer' unless value.is_a?(Integer) && value.between?(0, 0x7fffffffffffffff)

          value
        end

        private_class_method def self.credential(opts = {})
          id = identity(value: opts.fetch(:id))
          type = TYPES.key(opts.fetch(:type))
          algorithm = ALGORITHMS.key(opts.fetch(:algorithm))
          raise ResponseError, 'Unsupported OATH credential algorithm or type' unless type && algorithm

          period = type == :totp ? 30 : 0
          if type == :totp && (match = id.match(%r{\A([0-9]+)/}n))
            period = Integer(match[1], 10)
            raise ResponseError, 'Invalid OATH credential period' unless period.positive?
          end
          { id: id, account: id, oath_type: type, algorithm: algorithm, period: period }
        end

        private_class_method def self.list(opts = {})
          response = send_apdu(session: opts.fetch(:session), ins: 0xa1)
          credentials = Protocol.untlv(data: response).map do |entry|
            value = entry[:value]
            raise ResponseError, 'Malformed OATH LIST entry' unless entry[:tag] == 0x72 && value.bytesize.between?(2, 65)

            credential(id: value.byteslice(1..), type: value.getbyte(0) & 0xf0, algorithm: value.getbyte(0) & 0x0f)
          end
          raise ResponseError, 'Duplicate OATH account identifiers' unless credentials.map { |entry| entry[:id] }.uniq.length == credentials.length

          credentials
        end

        private_class_method def self.code_record(opts = {})
          credential = opts.fetch(:credential)
          timestamp = opts.fetch(:timestamp)
          challenge = credential[:oath_type] == :hotp ? ''.b : [timestamp / credential[:period]].pack('Q>')
          response = send_apdu(session: opts.fetch(:session), ins: 0xa2, p2: 1,
                               data: tlv(tag: 0x71, value: credential[:id]) + tlv(tag: 0x74, value: challenge))
          fields = Protocol.tlv_map(data: response)
          format_code(credential: credential, timestamp: timestamp, truncated: fields[0x76])
        end

        private_class_method def self.format_code(opts = {})
          truncated = opts[:truncated]
          raise ResponseError, 'Malformed OATH truncated response' unless truncated.is_a?(String) && truncated.bytesize == 5 && truncated.getbyte(0).between?(6, 8)

          digits = truncated.getbyte(0)
          number = (truncated.byteslice(1, 4).unpack1('N') & 0x7fffffff) % (10**digits)
          credential = opts.fetch(:credential)
          timestamp = opts.fetch(:timestamp)
          period = credential[:period]
          { value: number.to_s.rjust(digits, '0'), valid_from: period.positive? ? timestamp / period * period : timestamp,
            valid_to: period.positive? ? ((timestamp / period) + 1) * period : nil }
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts <<~HELP
            Execute native OATH management using in-memory secrets.
            #{self}.execute(
              args: 'optional - argv after oath; empty or group names return local metadata',
              connection: 'required - selected APDU handle except local help or forget --all',
              confirm: 'required - literal true for authentication, calculation, cache writes or mutations',
              password: 'optional - current access password as an in-memory String',
              access_key: 'optional - sixteen raw bytes instead of a current access password',
              new_password: 'optional - new in-memory access password for access change',
              new_access_key: 'optional - sixteen raw bytes instead of a new access password',
              secret: 'optional - raw 2 to 4096 byte OATH seed for accounts add',
              secret_base32: 'optional - strict Base32 encoding instead of raw secret',
              uri: 'optional - secret-bearing otpauth URI String for accounts uri, never argv',
              credentials: 'optional - array of complete credential Hash records for accounts import',
              pskc: 'optional - bounded in-memory PSKC 1.0 XML instead of credential records',
              pskc_key: 'optional - raw AES key for encrypted PSKC import',
              pskc_password: 'optional - password for PSKC embedded PBKDF2 parameters',
              encrypted_cache: 'optional - explicit encrypted? adapter with store/fetch/delete or clear/empty?',
              remember: 'optional - boolean handoff of a successfully validated access key to encrypted_cache',
              use_cache: 'optional - boolean use of the caller cache without password fallback',
              overwrite: 'optional - literal true to replace an existing exact OATH ID',
              generate: 'optional - boolean generation of a new seed, returned only in memory',
              touch: 'optional - boolean touch requirement when importing a credential',
              oath_type: 'optional - totp or hotp credential type for accounts add',
              algorithm: 'optional - SHA1, SHA256 or SHA512 for accounts add',
              digits: 'optional - integer from six through eight for accounts add',
              period: 'optional - positive integer TOTP period seconds, default thirty',
              counter: 'optional - initial uint32 HOTP counter, default zero',
              issuer: 'optional - exact issuer identity without colon for accounts add',
              secret_provider: 'optional - callable receiving the missing secret field Symbol after consent',
              timeout: 'optional - finite positive I/O timeout seconds'
            )
            Enumerate implemented operation leaves only.
            #{self}.operations
            Parse a strict otpauth URI locally without opening hardware.
            #{self}.parse_uri(uri: 'required - complete secret-bearing otpauth URI String')
            Calculate one exact account without substring matching.
            #{self}.code(
              connection: 'required - selected raw APDU transport handle',
              account: 'required - complete exact credential ID bytes including issuer and period',
              confirm: 'required - literal true for authentication or calculation',
              timestamp: 'optional - nonnegative Integer epoch seconds; defaults to now',
              password: 'optional - in-memory OATH access password when locked',
              access_key: 'optional - derived sixteen-byte raw access key instead of password',
              secret_provider: 'optional - callable receiving missing secret field Symbol',
              timeout: 'optional - finite positive I/O timeout seconds'
            )
            Calculate a raw HMAC response using one exact credential.
            #{self}.calculate(
              account: 'required - complete exact credential ID bytes',
              challenge: 'required - raw String of zero through sixty-four bytes',
              confirm: 'required - literal true for calculation; same access options as code'
            )
            Calculate all untouchable TOTP records without incrementing HOTP.
            #{self}.calculate_all(
              timestamp: 'optional - nonnegative Integer epoch seconds; defaults to now',
              confirm: 'required - literal true; same connection and access options as code'
            )
            Device writes are read back where possible; metadata verification does not prove seed contents.
            Remember/forget is a caller-owned encrypted storage handoff, never a built-in plaintext cache.
            Imports accept data in memory, not filenames. Unsupported PSKC algorithms/signatures fail closed.
            No mutation or authentication is retried, no corrupted account is repaired or deleted implicitly.
            Display module author information.
            #{self}.authors
          HELP
        end
      end
    end
  end
end
