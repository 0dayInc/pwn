# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'yaml'
require 'json'
require 'fileutils'
require 'securerandom'
require 'time'
require 'tempfile'
require 'tmpdir'

module PWN
  module Plugins
    # Used to encrypt/decrypt configuration files leveraging AES256
    module Vault
      CREDENTIAL_KDF_ITERATIONS = 600_000
      YUBIKEY_KDF = 'yubikey-hmac-sha1-hkdf-sha256'
      YUBIKEY_HEADER = "PWN-YUBIKEY-VAULT:1\n"

      # Returns an authenticated envelope; the caller persists only this value.
      # keyring is an injected OS-keyring reader responding to call(key_id).
      public_class_method def self.seal_credentials(opts = {})
        envelope = { 'version' => 1, 'cipher' => 'aes-256-gcm',
                     'kdf' => opts[:keyring] ? 'keyring' : 'pbkdf2-sha256',
                     'key_id' => opts[:key_id] || 'pwn-ai-credentials',
                     'iterations' => CREDENTIAL_KDF_ITERATIONS,
                     'salt' => Base64.strict_encode64(OpenSSL::Random.random_bytes(16)) }
        unless opts[:yubikey].nil?
          selector = yubikey_options(value: opts[:yubikey])
          raise ArgumentError, 'Choose YubiKey, passphrase, or keyring, not a combination' if opts[:passphrase] || opts[:keyring]

          envelope['kdf'] = YUBIKEY_KDF
          envelope['yubikey'] = selector.slice(:slot, :serial).transform_keys(&:to_s).merge('challenge' => Base64.strict_encode64(OpenSSL::Random.random_bytes(32)))
        end
        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.encrypt
        cipher.key = credential_key(opts.merge(envelope: envelope))
        envelope['iv'] = Base64.strict_encode64(cipher.random_iv)
        cipher.auth_data = credential_aad(envelope: envelope)
        plaintext = JSON.generate(opts.fetch(:credentials))
        envelope['ct'] = Base64.strict_encode64(cipher.update(plaintext) + cipher.final)
        envelope['tag'] = Base64.strict_encode64(cipher.auth_tag)
        envelope
      end

      # Decrypts in memory only. Does not modify or open any credential file.
      public_class_method def self.open_credentials(opts = {})
        envelope = opts.fetch(:envelope).transform_keys(&:to_s)
        raise ArgumentError, 'Unsupported credential envelope' unless envelope['version'] == 1 && envelope['cipher'] == 'aes-256-gcm'

        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.decrypt
        cipher.key = credential_key(opts.merge(envelope: envelope))
        cipher.iv = Base64.strict_decode64(envelope.fetch('iv'))
        tag = Base64.strict_decode64(envelope.fetch('tag'))
        raise ArgumentError, 'Invalid credential authentication tag' unless tag.bytesize == 16

        cipher.auth_tag = tag
        cipher.auth_data = credential_aad(envelope: envelope)
        JSON.parse(cipher.update(Base64.strict_decode64(envelope.fetch('ct'))) + cipher.final)
      rescue OpenSSL::Cipher::CipherError, JSON::ParserError
        raise ArgumentError, 'Credential authentication failed'
      end

      private_class_method def self.credential_key(opts = {})
        envelope = opts.fetch(:envelope)
        return yubikey_key(opts) if envelope['kdf'] == YUBIKEY_KDF

        raise ArgumentError, 'Envelope is not protected by YubiKey' unless opts[:yubikey].nil?

        if envelope['kdf'] == 'keyring'
          reader = opts[:keyring]
          raise ArgumentError, 'OS keyring reader required' unless reader.respond_to?(:call)

          key = reader.call(envelope.fetch('key_id'))
          raise ArgumentError, 'OS keyring must return a 32-byte key' unless key.is_a?(String) && key.bytesize == 32

          return key
        end
        raise ArgumentError, 'Unsupported credential KDF' unless envelope['kdf'] == 'pbkdf2-sha256'

        passphrase = opts[:passphrase].to_s
        raise ArgumentError, 'Credential passphrase required' if passphrase.empty?
        raise ArgumentError, 'Invalid credential KDF iterations' unless envelope['iterations'] == CREDENTIAL_KDF_ITERATIONS

        salt = Base64.strict_decode64(envelope.fetch('salt'))
        raise ArgumentError, 'Invalid credential salt' unless salt.bytesize == 16

        OpenSSL::PKCS5.pbkdf2_hmac(passphrase, salt, CREDENTIAL_KDF_ITERATIONS, 32, 'sha256')
      end

      private_class_method def self.yubikey_options(opts = {})
        value = opts[:value]
        raise ArgumentError, 'yubikey must be a selector Hash' unless value.is_a?(Hash)
        raise ArgumentError, 'YubiKey selector keys must be Strings or Symbols' unless value.keys.all? { |key| key.is_a?(String) || key.is_a?(Symbol) }

        selector = value.transform_keys(&:to_sym)
        raise ArgumentError, 'Unknown YubiKey selector option' unless (selector.keys - %i[slot serial timeout reader device_path connection]).empty?

        selector[:slot] = selector.fetch(:slot, 2)
        raise ArgumentError, 'YubiKey HMAC slot must be 1 or 2' unless selector[:slot].is_a?(Integer) && [1, 2].include?(selector[:slot])

        serial = selector[:serial]
        raise ArgumentError, 'YubiKey serial must be a decimal String' unless serial.nil? || (serial.is_a?(String) && serial.match?(/\A[0-9]+\z/))

        timeout = selector[:timeout]
        raise ArgumentError, 'YubiKey timeout must be finite positive seconds' unless timeout.nil? || ((timeout.is_a?(Integer) || timeout.is_a?(Float)) && timeout.finite? && timeout.positive?)

        %i[reader device_path].each do |field|
          name = selector[field]
          raise ArgumentError, "YubiKey #{field} must be a nonempty String without control characters" unless name.nil? || (name.is_a?(String) && name.valid_encoding? && !name.empty? && !name.match?(/[[:cntrl:]]/))
        end
        raise ArgumentError, 'YubiKey serial and reader selectors are mutually exclusive' if !serial.nil? && !selector[:reader].nil?
        raise ArgumentError, 'YubiKey reader and device_path selectors are mutually exclusive' if !selector[:reader].nil? && !selector[:device_path].nil?

        connection = selector[:connection]
        raise ArgumentError, 'YubiKey connection must respond to exchange' unless connection.nil? || connection.respond_to?(:exchange)

        selector
      end

      private_class_method def self.yubikey_key(opts = {})
        raise ArgumentError, 'Hardware envelopes do not accept software credentials' if opts[:passphrase] || opts[:keyring]

        envelope = opts.fetch(:envelope)
        metadata = envelope.fetch('yubikey')
        raise ArgumentError, 'Invalid YubiKey envelope metadata' unless metadata.is_a?(Hash) && (metadata.keys - %w[slot serial challenge]).empty?

        selector = yubikey_options(value: metadata.slice('slot', 'serial'))
        override = opts[:yubikey]
        unless override.nil?
          raise ArgumentError, 'yubikey must be a selector Hash' unless override.is_a?(Hash)

          override = yubikey_options(value: selector.merge(override.transform_keys(&:to_sym)))
          raise ArgumentError, 'YubiKey slot does not match the envelope' unless override[:slot] == selector[:slot]

          selector = selector.merge(override)
        end
        challenge = Base64.strict_decode64(metadata.fetch('challenge'))
        salt = Base64.strict_decode64(envelope.fetch('salt'))
        raise ArgumentError, 'Invalid YubiKey envelope challenge or salt' unless challenge.bytesize == 32 && salt.bytesize == 16

        response = PWN::Plugins::YubiKey.challenge_response(selector.merge(challenge: challenge))
        raise IOError, 'Invalid YubiKey HMAC response' unless response.is_a?(String) && response.bytesize == 20

        OpenSSL::KDF.hkdf(response, salt: salt, info: 'pwn-vault-credentials-v1', length: 32, hash: 'SHA256')
      end

      private_class_method def self.credential_aad(opts = {})
        envelope = opts.fetch(:envelope)
        JSON.generate(envelope.except('ct', 'tag').sort.to_h)
      end

      # Ciphertext-only callers use these primitives without a plaintext file stage.
      public_class_method def self.encrypt_data(opts = {})
        data = opts.fetch(:data)
        raise ArgumentError, 'data must be a String' unless data.is_a?(String)

        unless opts[:yubikey].nil?
          raise ArgumentError, 'YubiKey encryption does not accept a software key or IV' if opts[:key] || opts[:iv]

          envelope = seal_credentials(credentials: { 'data' => Base64.strict_encode64(data) }, yubikey: opts[:yubikey])
          return "#{YUBIKEY_HEADER}#{JSON.generate(envelope)}\n"
        end
        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.encrypt
        cipher.key = Base64.strict_decode64(opts[:key] || PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Key'))
        cipher.iv = Base64.strict_decode64(opts[:iv] || PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'IV'))
        "#{Base64.strict_encode64((data.empty? ? ''.b : cipher.update(data)) + cipher.final)}\n"
      end

      public_class_method def self.decrypt_data(opts = {})
        data = opts.fetch(:data)
        raise ArgumentError, 'data must be a String' unless data.is_a?(String)

        if data.start_with?('PWN-YUBIKEY-VAULT:')
          raise ArgumentError, 'Hardware vaults do not accept a software key or IV' if opts[:key] || opts[:iv]

          envelope = hardware_envelope(data: data)
          return Base64.strict_decode64(open_credentials(envelope: envelope, yubikey: opts[:yubikey]).fetch('data'))
        end
        raise ArgumentError, 'Vault is not protected by YubiKey' unless opts[:yubikey].nil?

        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.decrypt
        cipher.key = Base64.strict_decode64(opts[:key] || PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Key'))
        cipher.iv = Base64.strict_decode64(opts[:iv] || PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'IV'))
        cipher.update(Base64.strict_decode64(data.chomp)) + cipher.final
      end

      public_class_method def self.hardware_encrypted?(opts = {})
        data = opts[:data] || File.binread(opts.fetch(:file), YUBIKEY_HEADER.bytesize)
        data.start_with?('PWN-YUBIKEY-VAULT:')
      end

      # Resolve a self-describing hardware vault or a legacy key/IV sidecar.
      # Never prompt or read a software decryptor for a hardware envelope.
      public_class_method def self.access_options(opts = {})
        file = opts.fetch(:file)
        if hardware_encrypted?(file: file)
          raise ArgumentError, 'Hardware vaults do not accept a software key or IV' if opts[:key] || opts[:iv]

          metadata = hardware_envelope(data: File.binread(file)).fetch('yubikey')
          selector = metadata.slice('slot', 'serial').transform_keys(&:to_sym)
          unless opts[:yubikey].nil?
            raise ArgumentError, 'yubikey must be a selector Hash' unless opts[:yubikey].is_a?(Hash)

            selector = selector.merge(opts[:yubikey].transform_keys(&:to_sym))
          end
          return { yubikey: yubikey_options(value: selector) }
        end
        raise ArgumentError, 'Vault is not protected by YubiKey' unless opts[:yubikey].nil?

        key = opts[:key]
        iv = opts[:iv]
        path = opts[:decryptor_file] || "#{file}.decryptor"
        if (!key || !iv) && File.file?(path)
          sidecar = YAML.safe_load_file(path, permitted_classes: [Symbol], aliases: false, symbolize_names: true)
          raise ArgumentError, 'Invalid vault decryptor' unless sidecar.is_a?(Hash)

          key ||= sidecar[:key]
          iv ||= sidecar[:iv]
        end
        key ||= ENV.fetch('PWN_DECRYPTOR_KEY', nil)
        iv ||= ENV.fetch('PWN_DECRYPTOR_IV', nil)
        raise ArgumentError, 'Vault key and IV required' unless key.is_a?(String) && iv.is_a?(String) && !key.empty? && !iv.empty?

        { key: key, iv: iv }
      end

      # Mutate a YAML document in memory and atomically publish only ciphertext.
      public_class_method def self.update(opts = {})
        file = File.expand_path(opts.fetch(:file))
        with_vault_lock(file: file) do
          bytes = File.binread(file)
          access = access_options(opts)
          plaintext = decrypt_data(access.merge(data: bytes)).force_encoding(Encoding::UTF_8)
          document = YAML.safe_load(plaintext, permitted_classes: [Symbol], aliases: true, symbolize_names: true)
          raise ArgumentError, 'Vault configuration must be a mapping' unless document.is_a?(Hash)

          yield document
          ciphertext = encrypt_data(access.merge(data: YAML.dump(document)))
          publish_data(file: file, data: ciphertext, expected: bytes)
        end
        :saved
      end

      private_class_method def self.hardware_envelope(opts = {})
        data = opts.fetch(:data)
        raise ArgumentError, 'Unsupported YubiKey vault format' unless data.start_with?(YUBIKEY_HEADER)

        envelope = JSON.parse(data.delete_prefix(YUBIKEY_HEADER))
        raise ArgumentError, 'Invalid YubiKey vault envelope' unless envelope.is_a?(Hash) && envelope['kdf'] == YUBIKEY_KDF

        envelope
      end

      # Share the editor's stable directory lock. Reentrancy is internal, never an
      # option callers can supply to bypass locking; inode identity covers aliases.
      private_class_method def self.with_vault_lock(opts = {})
        path = File.expand_path(opts.fetch(:file))
        File.open(File.dirname(path), File::RDONLY) do |lock|
          stat = lock.stat
          identity = [Process.pid, stat.dev, stat.ino]
          held = Thread.current[:pwn_vault_locks] ||= {}
          return yield if held.key?(identity)

          lock.flock(File::LOCK_EX)
          begin
            held[identity] = lock
            yield
          ensure
            held.delete(identity)
            Thread.current[:pwn_vault_locks] = nil if held.empty?
            lock.flock(File::LOCK_UN)
          end
        end
      end

      private_class_method def self.publish_data(opts = {})
        path = File.expand_path(opts.fetch(:file))
        with_vault_lock(file: path) do
          stat = File.lstat(path)
          raise IOError, 'Vault must be an owned regular file without links' unless stat.file? && stat.uid == Process.uid && stat.nlink == 1

          Tempfile.create(['.pwn-vault-', '.tmp'], File.dirname(path)) do |temp|
            temp.binmode
            temp.chmod(0o600)
            temp.write(opts.fetch(:data))
            temp.flush
            temp.fsync
            raise IOError, 'Vault changed before replacement' unless File.lstat(path).ino == stat.ino && File.binread(path) == opts.fetch(:expected)

            File.rename(temp.path, path)
            File.open(File.dirname(path), File::RDONLY, &:fsync)
          end
        end
        opts.fetch(:data).bytesize
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.refresh_encryption_secrets(
      #   file: 'required - file to encrypt with new key and iv',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt'
      # )

      public_class_method def self.refresh_encryption_secrets(opts = {})
        destination = yubikey_options(value: opts[:new_yubikey]) unless opts[:new_yubikey].nil?
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        raise ArgumentError, 'Legacy vault conversion to YubiKey requires new_yubikey, not yubikey' if !opts[:yubikey].nil? && !hardware_encrypted?(file: file)

        if !destination.nil? || hardware_encrypted?(file: file)
          bytes = File.binread(file)
          access = access_options(opts.merge(file: file))
          plaintext = decrypt_data(access.merge(data: bytes))
          selector = destination || access.fetch(:yubikey)
          ciphertext = encrypt_data(data: plaintext, yubikey: selector)
          return publish_data(file: file, data: ciphertext, expected: bytes)
        end
        key = opts[:key]
        iv = opts[:iv]

        decrypt(
          file: file,
          key: key,
          iv: iv
        )

        create(
          file: file
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.create(
      #   file: 'required - encrypted file to create',
      #   decryptor_file: 'optional - file to save the key && iv values'
      # )

      public_class_method def self.create(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        unless opts[:yubikey].nil?
          raise ArgumentError, 'A YubiKey vault does not use a decryptor file' if opts[:decryptor_file]
          raise ArgumentError, 'YubiKey encryption does not accept a software key or IV' if opts[:key] || opts[:iv]

          return encrypt(file: file, yubikey: opts[:yubikey])
        end
        decryptor_file = opts[:decryptor_file]

        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        key = Base64.strict_encode64(cipher.random_key)
        iv = Base64.strict_encode64(cipher.random_iv)

        if decryptor_file
          decryptor_hash = { key: key, iv: iv }
          yaml_decryptor = YAML.dump(decryptor_hash).gsub(/^(\s*):/, '\1')
          File.write(decryptor_file, yaml_decryptor)
          # Change permissions to 400
          File.chmod(0o400, decryptor_file)
        else
          puts 'Please store the Key && IV in a secure location as they are required for decryption.'
          puts "Key: #{key}"
          puts "IV: #{iv}"
        end

        encrypt(
          file: file,
          key: key,
          iv: iv
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.decrypt(
      #   file: 'required - file to decrypt',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt'
      # )

      public_class_method def self.decrypt(opts = {})
        file = opts.fetch(:file)
        bytes = File.binread(file)
        plaintext = decrypt_data(opts.merge(data: bytes))
        publish_data(file: file, data: plaintext, expected: bytes)
      end

      # Supported Method Parameters::
      # vault = PWN::Plugins::Vault.dump(
      #   file: 'required - file to dump',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt',
      #   yaml: 'optional - dump as parsed yaml hash (default: true)'
      # )

      public_class_method def self.dump(opts = {})
        plaintext = decrypt_data(opts.merge(data: File.binread(opts.fetch(:file))))
        opts[:yaml] == false ? plaintext : YAML.safe_load(plaintext.force_encoding(Encoding::UTF_8), permitted_classes: [Symbol], aliases: true, symbolize_names: true)
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.edit(
      #   file: 'required - file to edit',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt',
      #   editor: 'optional - editor to use (default: "/usr/bin/vim")'
      # )

      public_class_method def self.edit(opts = {})
        file = File.expand_path(opts.fetch(:file))
        raise ArgumentError, 'Vault is not protected by YubiKey' if !opts[:yubikey].nil? && !hardware_encrypted?(file: file)

        editor = opts[:editor] || '/usr/bin/vim'
        raise 'ERROR: Editor not found.' unless File.executable?(editor)

        bytes = File.binread(file)
        access = if hardware_encrypted?(data: bytes)
                   access_options(opts)
                 else
                   { key: opts[:key] || PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Key'),
                     iv: opts[:iv] || PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'IV') }
                 end
        plaintext = decrypt_data(access.merge(data: bytes))
        runtime = File.join(Dir.home, '.pwn', 'workspaces', 'runtime')
        FileUtils.mkdir_p(runtime, mode: 0o700)
        Dir.mktmpdir('pwn-vault-edit-', runtime) do |directory|
          temporary = File.join(directory, 'vault.yaml')
          File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |io| io.write(plaintext) }
          raise IOError, 'Vault editor failed; original ciphertext retained' unless system(editor, temporary)

          ciphertext = encrypt_data(access.merge(data: File.binread(temporary)))
          publish_data(file: file, data: ciphertext, expected: bytes)
        end
        Pry.config.refresh_pwn_env = true if defined?(Pry)
        :saved
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.encrypt(
      #   file: 'required - file to encrypt',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt'
      # )

      public_class_method def self.encrypt(opts = {})
        file = opts.fetch(:file)
        bytes = File.binread(file)
        ciphertext = encrypt_data(opts.merge(data: bytes))
        publish_data(file: file, data: ciphertext, expected: bytes)
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.file_encrypted?(
      #   file: 'required - file to check if encrypted'
      # )
      public_class_method def self.file_encrypted?(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)

        raise 'ERROR: File does not exist.' unless File.exist?(file)

        file_contents = File.read(file).chomp
        return true if hardware_encrypted?(data: file_contents)

        file_contents.is_a?(String) && Base64.strict_encode64(Base64.strict_decode64(file_contents)) == file_contents
      rescue ArgumentError
        false
      rescue StandardError => e
        raise e
      end

      # Store an engagement-scoped secret with host, finding, and source provenance.
      public_class_method def self.store(opts = {})
        secret = opts[:secret].to_s
        raise 'ERROR: secret is required' if secret.empty?

        eng = engagement_id(opts)
        label = opts[:label].to_s
        label = "#{opts[:host] || 'loot'}:#{opts[:username] || 'user'}:#{SecureRandom.hex(4)}" if label.empty?
        records = load_records(engagement: eng)
        selector = opts[:yubikey]
        prior = records.find { |row| row[:label] == label }
        envelope = prior && prior[:secret]
        if selector.nil? && envelope.is_a?(Hash) && (envelope[:kdf] || envelope['kdf']) == YUBIKEY_KDF
          metadata = envelope[:yubikey] || envelope['yubikey']
          selector = metadata.transform_keys(&:to_sym).slice(:slot, :serial)
        end
        record = {
          id: SecureRandom.hex(6),
          label: label,
          kind: (opts[:kind] || 'password').to_s,
          engagement: eng,
          host: opts[:host].to_s,
          service: opts[:service].to_s,
          username: opts[:username].to_s,
          secret: encrypt_secret(secret: secret, yubikey: selector),
          source: (opts[:source] || 'manual').to_s,
          where: (opts[:where] || opts[:path]).to_s,
          finding_id: (opts[:finding_id] || opts[:finding]).to_s,
          at: Time.now.utc.iso8601
        }
        records.reject! { |row| row[:label] == label }
        records << record
        save_records(engagement: eng, records: records)
        note_mission_loot(handle: record[:id], host: opts[:host])
        record.except(:secret).merge(stored: true)
      end

      private_class_method def self.note_mission_loot(opts = {})
        return unless defined?(PWN::AI::Agent::Mission)

        mid = PWN::AI::Agent::Mission.active_id
        return if mid.to_s.empty?

        PWN::AI::Agent::Mission.note_loot!(id: mid, handle: opts[:handle], host: opts[:host])
      rescue StandardError
        nil
      end

      public_class_method def self.fetch(opts = {})
        label = opts[:label].to_s
        raise 'ERROR: label is required' if label.empty?

        rows = opts[:engagement] || opts[:engagement_id] ? load_records(opts) : load_all_records
        row = rows.find { |item| item[:label] == label }
        return nil unless row

        decrypt_secret(row: row[:secret] || row, yubikey: opts[:yubikey])
      end

      # List loot metadata for lateral-movement planning (no plaintext secrets).
      public_class_method def self.query(opts = {})
        host = opts[:host].to_s.downcase
        service = opts[:service].to_s
        kind = opts[:kind].to_s
        finding = (opts[:finding_id] || opts[:finding]).to_s
        load_records(opts).filter_map do |row|
          next if !host.empty? && !host_match?(host: host, row: row)
          next if !service.empty? && !row[:service].to_s.empty? && row[:service].to_s != service
          next if !kind.empty? && row[:kind].to_s != kind
          next if !finding.empty? && row[:finding_id].to_s != finding

          row.except(:secret).merge(has_secret: true)
        end
      end

      # Return decrypted creds that match a service auth prompt.
      public_class_method def self.offer(opts = {})
        query(
          host: opts[:host],
          service: opts[:service],
          kind: opts[:kind],
          finding_id: opts[:finding_id] || opts[:finding],
          engagement: opts[:engagement] || opts[:engagement_id]
        ).map do |row|
          row.merge(secret: fetch(label: row[:label], engagement: row[:engagement], yubikey: opts[:yubikey]))
        end
      end

      # Parse username/password (or token) strings from recon evidence into the loot store.
      public_class_method def self.ingest(opts = {})
        text = opts[:text].to_s
        username = text[/\buser(?:name)?\s*[=:]\s*(\S+)/i, 1]
        password = text[/\b(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*(\S+)/i, 1]
        return [] if password.to_s.empty?

        [store(opts.merge(username: username, secret: password.to_s.sub(/[.,;]+$/, ''), kind: opts[:kind] || 'password'))]
      end

      public_class_method def self.expand(opts = {})
        text = opts[:text].to_s
        text.gsub(/\{\{vault:([^}]+)\}\}/) { fetch(label: Regexp.last_match(1).to_s.strip, yubikey: opts[:yubikey]).to_s }
      end

      public_class_method def self.redact(opts = {})
        text = opts[:text].to_s
        load_all_records.each do |row|
          val = decrypt_secret(row: row[:secret] || row, yubikey: opts[:yubikey]).to_s
          next if val.empty?

          text = text.gsub(val, "{{vault:#{row[:label]}}}")
        end
        text
      end

      private_class_method def self.engagement_id(opts = {})
        value = (opts[:engagement] || opts[:engagement_id] || 'default').to_s
        value = 'default' if value.empty?
        raise ArgumentError, 'engagement_id must be a simple identifier' unless value.match?(/\A[a-zA-Z0-9_-]+\z/)

        value
      end

      private_class_method def self.host_match?(opts = {})
        want = opts[:host].to_s.downcase
        have = opts[:row][:host].to_s.downcase
        return false if have.empty?

        have == want || have.end_with?(".#{want}") || want.end_with?(".#{have}")
      end

      private_class_method def self.key_path
        File.join(Dir.home, '.pwn-vault.key')
      end

      private_class_method def self.box_path(opts = {})
        File.join(Dir.home, '.pwn', 'engagements', engagement_id(opts), 'loot.json')
      end

      private_class_method def self.legacy_box_path(opts = {})
        _n = opts[:n]
        File.join(Dir.home, '.pwn', 'vault-secrets.json')
      end

      private_class_method def self.master_key(opts = {})
        _n = opts[:n]
        path = key_path
        unless File.file?(path)
          File.binwrite(path, OpenSSL::Random.random_bytes(32))
          File.chmod(0o600, path)
        end
        File.binread(path)
      end

      private_class_method def self.encrypt_secret(opts = {})
        return seal_credentials(credentials: { 'secret' => opts[:secret].to_s }, yubikey: opts[:yubikey]) unless opts[:yubikey].nil?

        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.encrypt
        cipher.key = master_key
        iv = cipher.random_iv
        cipher.auth_data = 'pwn-vault'
        ct = cipher.update(opts[:secret].to_s) + cipher.final
        { iv: Base64.strict_encode64(iv), ct: Base64.strict_encode64(ct), tag: Base64.strict_encode64(cipher.auth_tag) }
      end

      private_class_method def self.decrypt_secret(opts = {})
        row = opts[:row]
        return '' unless row.is_a?(Hash)

        hardware = row.key?(:kdf) || row.key?('kdf')
        if hardware
          envelope = row.transform_keys(&:to_s)
          envelope['yubikey'] = envelope['yubikey'].transform_keys(&:to_s) if envelope['yubikey'].is_a?(Hash)
          return open_credentials(envelope: envelope, yubikey: opts[:yubikey]).fetch('secret')
        end
        raise ArgumentError, 'Loot is not protected by YubiKey' unless opts[:yubikey].nil?

        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.decrypt
        cipher.key = master_key
        cipher.iv = Base64.strict_decode64(row[:iv] || row['iv'].to_s)
        cipher.auth_tag = Base64.strict_decode64(row[:tag] || row['tag'].to_s)
        cipher.auth_data = 'pwn-vault'
        cipher.update(Base64.strict_decode64(row[:ct] || row['ct'].to_s)) + cipher.final
      rescue StandardError
        raise if hardware || opts[:yubikey]

        ''
      end

      private_class_method def self.load_records(opts = {})
        path = box_path(opts)
        rows = parse_box(path: path)
        rows.concat(parse_box(path: legacy_box_path)) if engagement_id(opts) == 'default' && path != legacy_box_path
        rows
      end

      private_class_method def self.load_all_records(opts = {})
        _n = opts[:n]
        paths = Dir.glob(File.join(Dir.home, '.pwn', 'engagements', '*', 'loot.json'))
        paths << legacy_box_path
        paths.uniq.flat_map { |path| parse_box(path: path) }
      end

      private_class_method def self.parse_box(opts = {})
        path = opts[:path].to_s
        stat = begin
          File.lstat(path)
        rescue Errno::ENOENT
          nil
        end
        return [] unless stat

        invalid = "Invalid loot store #{path}"
        raise IOError, "#{invalid}: expected a regular file" unless stat.file?

        data = JSON.parse(File.read(path), symbolize_names: true)
        raise IOError, "#{invalid}: expected a mapping" unless data.is_a?(Hash)

        if data[:records].is_a?(Array)
          raise IOError, "#{invalid}: unsupported version" if data.key?(:version) && data[:version] != 2

          rows = data[:records].map do |row|
            next row unless row.is_a?(Hash) && !row.key?(:secret)

            # Strip only record metadata so unknown KDFs and hardware fields still
            # reach envelope validation rather than becoming software ciphertext.
            secret = row.except(:id, :label, :kind, :engagement, :host, :service, :username, :source, :where, :finding_id, :at)
            row.except(*secret.keys).merge(secret: secret)
          end
          raise IOError, "#{invalid}: invalid record or secret envelope" unless rows.all? { |row| row.is_a?(Hash) && row[:label].is_a?(String) && !row[:label].empty? && valid_loot_secret?(secret: row[:secret]) }

          rows
        else
          raise IOError, "#{invalid}: invalid legacy secret envelope" unless data.all? { |label, row| !label.to_s.empty? && valid_loot_secret?(secret: row) }

          data.map do |label, row|
            { label: label.to_s, secret: row, engagement: 'default', host: '', source: 'legacy' }
          end
        end
      rescue JSON::ParserError
        raise IOError, "Invalid loot store #{path}: malformed JSON", cause: nil
      rescue SystemCallError => e
        raise IOError, "Cannot read loot store #{path} (#{e.class})", cause: nil
      end

      # Validate storage shape without unlocking secrets or accepting an unknown backend.
      private_class_method def self.valid_loot_secret?(opts = {})
        secret = opts[:secret]
        return false unless secret.is_a?(Hash) && %i[iv ct tag].all? { |key| secret[key].is_a?(String) && !secret[key].empty? }
        return true if (secret.keys - %i[iv ct tag]).empty?
        return false unless secret[:kdf] == YUBIKEY_KDF && secret[:version] == 1 && secret[:cipher] == 'aes-256-gcm'
        return false unless %i[salt key_id].all? { |key| secret[key].is_a?(String) && !secret[key].empty? }

        metadata = secret[:yubikey]
        return false unless metadata.is_a?(Hash) && (metadata.keys - %i[slot serial challenge]).empty? && metadata[:slot].is_a?(Integer) && [1, 2].include?(metadata[:slot])
        return false unless metadata[:challenge].is_a?(String) && !metadata[:challenge].empty?

        metadata[:serial].nil? || (metadata[:serial].is_a?(String) && metadata[:serial].match?(/\A[0-9]+\z/))
      end

      private_class_method def self.save_records(opts = {})
        path = box_path(opts)
        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, JSON.pretty_generate(version: 2, records: opts[:records] || []))
        File.chmod(0o600, path)
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          # Seal credentials in an authenticated AES256GCM envelope, without filesystem access.
          #{self}.seal_credentials(
            credentials: 'required - JSON-compatible credentials hash',
            passphrase: 'optional - required unless keyring or yubikey is supplied',
            keyring: 'optional - callable OS keyring reader returning a raw 32-byte key',
            yubikey: 'optional - native hardware selector Hash: Integer slot (1 or 2), exact decimal String serial, nonempty control-free reader/device_path, exchange-capable connection and finite positive timeout; serial/reader and reader/device_path are mutually exclusive; only slot/serial persist; requires a provisioned HMAC-SHA1 slot',
            key_id: 'optional - keyring identifier, default pwn-ai-credentials'
          )
          # Open an authenticated envelope in memory; never writes plaintext.
          #{self}.open_credentials(
            envelope: 'required - sealed credentials hash',
            passphrase: 'optional - required for passphrase envelopes',
            keyring: 'optional - callable OS keyring reader for keyring envelopes',
            yubikey: 'optional - runtime hardware selector; defaults to the stored slot and serial'
          )
          # Encrypt bytes in memory using a legacy key and IV or a YubiKey-authenticated envelope.
          #{self}.encrypt_data(
            data: 'required - plaintext String, including binary data',
            key: 'optional - Base64 AES key for legacy CBC encryption only',
            iv: 'optional - Base64 IV for legacy CBC encryption only',
            yubikey: 'optional - hardware selector Hash; excludes software key and IV'
          )
          # Authenticate and decrypt bytes in memory without a software fallback for hardware envelopes.
          #{self}.decrypt_data(
            data: 'required - encrypted String returned by encrypt_data',
            key: 'optional - legacy Base64 AES key',
            iv: 'optional - legacy Base64 IV',
            yubikey: 'optional - runtime hardware selector Hash for the stored slot'
          )
          # Identify hardware envelopes without using a device or decryptor.
          #{self}.hardware_encrypted?(
            file: 'optional - existing file path when data is not supplied',
            data: 'optional - encrypted String to inspect instead of a file'
          )
          # Resolve hardware selectors or legacy credentials without prompting.
          #{self}.access_options(
            file: 'required - existing encrypted vault path',
            decryptor_file: 'optional - legacy sidecar path, default file.decryptor',
            key: 'optional - explicit legacy key overrides the sidecar',
            iv: 'optional - explicit legacy IV overrides the sidecar',
            yubikey: 'optional - runtime selector Hash for a hardware envelope'
          )
          # Yield a YAML mapping for in-memory edits and atomically save ciphertext only.
          #{self}.update(
            file: 'required - encrypted YAML file; mutate the mapping yielded to the block',
            decryptor_file: 'optional - legacy key and IV sidecar path',
            key: 'optional - explicit legacy Base64 key',
            iv: 'optional - explicit legacy Base64 IV',
            yubikey: 'optional - hardware selector override; file format is preserved'
          ) { |document| ... }
          # Rewrap hardware ciphertext with fresh randomness or explicitly convert legacy encryption to hardware.
          #{self}.refresh_encryption_secrets(
            file: 'required - file to encrypt with new key and iv',
            key: 'optional - legacy key to decrypt',
            iv: 'optional - legacy IV to decrypt',
            yubikey: 'optional - current hardware selector; defaults to the envelope metadata',
            new_yubikey: 'optional - destination hardware selector; never provisions or rotates a device slot'
          )

          # Run create and return its result
          #{self}.create(
            file: 'required - encrypted file to create',
            decryptor_file: 'optional - file to save legacy key and IV; omit for hardware vaults',
            yubikey: 'optional - hardware selector Hash instead of generating software secrets'
          )

          # Run decrypt and return its result
          #{self}.decrypt(
            file: 'required - file to decrypt',
            key: 'optional - legacy key to decrypt',
            iv: 'optional - legacy IV to decrypt',
            yubikey: 'optional - runtime hardware selector; hardware format is auto-detected'
          )

          # Run dump and return its result
          #{self}.dump(
            file: 'required - file to dump',
            key: 'optional - legacy key to decrypt',
            iv: 'optional - legacy IV to decrypt',
            yubikey: 'optional - hardware selector Hash; no plaintext file is created',
            yaml: 'optional - dump as parsed yaml hash (default: true)'
          )

          # Run edit and return its result
          #{self}.edit(
            file: 'required - file to edit',
            key: 'optional - legacy key to decrypt',
            iv: 'optional - legacy IV to decrypt',
            yubikey: 'optional - hardware selector; original ciphertext stays intact until the temporary edited copy is re-encrypted',
            editor: 'optional - editor to use (default: /usr/bin/vim)'
          )

          # Run encrypt and return its result
          #{self}.encrypt(
            file: 'required - file to encrypt',
            key: 'optional - legacy key for encryption',
            iv: 'optional - legacy IV for encryption',
            yubikey: 'optional - hardware selector Hash selecting authenticated encryption instead of legacy CBC'
          )

          # Run file encrypted and return its result
          #{self}.file_encrypted?(
            file: 'required - file to check if encrypted'
          )

          # Store a secret outside the transcript using AES-GCM with hardware or a local master key.
          #{self}.store(
            secret: 'required - secret value (password, token, or key material)',
            yubikey: 'optional - hardware selector Hash; no disk master key; replacing a hardware label preserves protection',
            label: 'optional - vault label; defaults to host:user:hex',
            engagement: 'optional - engagement id scoping the loot file (defaults to default)',
            engagement_id: 'optional - alias for engagement',
            host: 'optional - hostname or IP this secret authenticates',
            service: 'optional - service name such as http or ssh',
            username: 'optional - account name recovered with the secret',
            kind: 'optional - password, token, or key (defaults to password)',
            source: 'optional - provenance source such as recon or redaction',
            where: 'optional - URL, banner, or path where the secret was found',
            path: 'optional - alias for where',
            finding_id: 'optional - finding id this secret is linked to',
            finding: 'optional - alias for finding_id'
          )

          # Fetch a stored secret by label.
          #{self}.fetch(
            label: 'required - vault label',
            yubikey: 'optional - runtime hardware selector; hardware failures raise without software fallback',
            engagement: 'optional - engagement id to search first',
            engagement_id: 'optional - alias for engagement'
          )

          # List loot metadata for lateral-movement planning without plaintext secrets.
          #{self}.query(
            host: 'optional - hostname or IP to match',
            service: 'optional - service name such as http or ssh',
            kind: 'optional - password, token, or key',
            finding_id: 'optional - finding id this secret is linked to',
            finding: 'optional - alias for finding_id',
            engagement: 'optional - engagement id scoping the loot file (defaults to default)',
            engagement_id: 'optional - alias for engagement'
          )

          # Return decrypted creds that match a service auth prompt.
          #{self}.offer(
            host: 'optional - hostname or IP to match',
            yubikey: 'optional - hardware selector forwarded when decrypting matching loot',
            service: 'optional - service name such as http or ssh',
            kind: 'optional - password, token, or key',
            finding_id: 'optional - finding id this secret is linked to',
            finding: 'optional - alias for finding_id',
            engagement: 'optional - engagement id scoping the loot file (defaults to default)',
            engagement_id: 'optional - alias for engagement'
          )

          # Parse username/password strings from recon evidence into the loot store.
          #{self}.ingest(
            text: 'required - recon banner, .env, or HTML containing creds',
            yubikey: 'optional - hardware selector to encrypt extracted loot',
            host: 'optional - hostname or IP this secret authenticates',
            service: 'optional - service name such as http or ssh',
            source: 'optional - provenance source such as recon',
            where: 'optional - URL, banner, or path where the secret was found',
            engagement: 'optional - engagement id scoping the loot file (defaults to default)',
            engagement_id: 'optional - alias for engagement',
            finding_id: 'optional - finding id this secret is linked to',
            kind: 'optional - password, token, or key (defaults to password)',
            label: 'optional - vault label; defaults to host:user:hex'
          )

          # Replace {{vault:label}} tokens with stored secrets.
          #{self}.expand(
            text: 'required - string possibly containing {{vault:label}} tokens',
            yubikey: 'optional - hardware selector for referenced loot'
          )

          # Replace stored secret values with {{vault:label}} placeholders.
          #{self}.redact(
            text: 'required - string that may contain stored secrets',
            yubikey: 'optional - hardware selector for stored hardware loot; may require physical touch'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
