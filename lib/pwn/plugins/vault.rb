# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'yaml'
require 'json'
require 'fileutils'
require 'securerandom'
require 'time'

module PWN
  module Plugins
    # Used to encrypt/decrypt configuration files leveraging AES256
    module Vault
      CREDENTIAL_KDF_ITERATIONS = 600_000

      # Returns an authenticated envelope; the caller persists only this value.
      # keyring is an injected OS-keyring reader responding to call(key_id).
      public_class_method def self.seal_credentials(opts = {})
        envelope = { 'version' => 1, 'cipher' => 'aes-256-gcm',
                     'kdf' => opts[:keyring] ? 'keyring' : 'pbkdf2-sha256',
                     'key_id' => opts[:key_id] || 'pwn-ai-credentials',
                     'iterations' => CREDENTIAL_KDF_ITERATIONS,
                     'salt' => Base64.strict_encode64(OpenSSL::Random.random_bytes(16)) }
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

      private_class_method def self.credential_aad(opts = {})
        envelope = opts.fetch(:envelope)
        JSON.generate(envelope.except('ct', 'tag').sort.to_h)
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.refresh_encryption_secrets(
      #   file: 'required - file to encrypt with new key and iv',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt'
      # )

      public_class_method def self.refresh_encryption_secrets(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
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
      rescue ArgumentError
        raise 'ERROR: Incorrect Key or IV.'
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
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        key = opts[:key] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Key'
        )

        iv = opts[:iv] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'IV'
        )

        is_encrypted = file_encrypted?(file: file)
        raise 'ERROR: File is not encrypted.' unless is_encrypted

        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.decrypt
        cipher.key = Base64.strict_decode64(key)
        cipher.iv = Base64.strict_decode64(iv)

        b64_decoded_file_contents = Base64.strict_decode64(File.read(file).chomp)
        plain_text = cipher.update(b64_decoded_file_contents) + cipher.final

        File.write(file, plain_text)
      rescue ArgumentError
        raise 'ERROR: Incorrect Key or IV.'
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # vault = PWN::Plugins::Vault.dump(
      #   file: 'required - file to dump',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt',
      #   yaml: 'optional - dump as parsed yaml hash (default: true)'
      # )

      public_class_method def self.dump(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        key = opts[:key] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Key'
        )

        iv = opts[:iv] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'IV'
        )

        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.decrypt
        cipher.key = Base64.strict_decode64(key)
        cipher.iv = Base64.strict_decode64(iv)
        bytes = Base64.strict_decode64(File.read(file).chomp)
        plaintext = cipher.update(bytes) + cipher.final
        opts[:yaml] == false ? plaintext : YAML.safe_load(plaintext, permitted_classes: [Symbol], aliases: true, symbolize_names: true)
      rescue ArgumentError
        raise 'ERROR: Incorrect Key or IV.'
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.edit(
      #   file: 'required - file to edit',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt',
      #   editor: 'optional - editor to use (default: "/usr/bin/vim")'
      # )

      public_class_method def self.edit(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        key = opts[:key] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Key'
        )

        iv = opts[:iv] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'IV'
        )

        editor = opts[:editor] ||= '/usr/bin/vim'

        raise 'ERROR: Editor not found.' unless File.exist?(editor)

        decrypt(
          file: file,
          key: key,
          iv: iv
        )

        # Get realtive editor in case aliases are used
        relative_editor = File.basename(editor)
        system(relative_editor, file)

        # If the Pry object exists, set refresh_config to true
        Pry.config.refresh_pwn_env = true if defined?(Pry)

        encrypt(
          file: file,
          key: key,
          iv: iv
        )
      rescue ArgumentError
        raise 'ERROR: Incorrect Key or IV.'
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.encrypt(
      #   file: 'required - file to encrypt',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt'
      # )

      public_class_method def self.encrypt(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        key = opts[:key] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Key'
        )

        iv = opts[:iv] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'IV'
        )

        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.encrypt
        cipher.key = Base64.strict_decode64(key)
        cipher.iv = Base64.strict_decode64(iv)

        data = File.read(file)
        encrypted = cipher.update(data) + cipher.final
        encrypted_string = Base64.strict_encode64(encrypted)

        File.write(file, "#{encrypted_string}\n")
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.file_encrypted?(
      #   file: 'required - file to check if encrypted'
      # )
      public_class_method def self.file_encrypted?(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)

        raise 'ERROR: File does not exist.' unless File.exist?(file)

        file_contents = File.read(file).chomp
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
        record = {
          id: SecureRandom.hex(6),
          label: label,
          kind: (opts[:kind] || 'password').to_s,
          engagement: eng,
          host: opts[:host].to_s,
          service: opts[:service].to_s,
          username: opts[:username].to_s,
          secret: encrypt_secret(secret: secret),
          source: (opts[:source] || 'manual').to_s,
          where: (opts[:where] || opts[:path]).to_s,
          finding_id: (opts[:finding_id] || opts[:finding]).to_s,
          at: Time.now.utc.iso8601
        }
        records.reject! { |row| row[:label] == label }
        records << record
        save_records(engagement: eng, records: records)
        record.except(:secret).merge(stored: true)
      end

      public_class_method def self.fetch(opts = {})
        label = opts[:label].to_s
        raise 'ERROR: label is required' if label.empty?

        rows = opts[:engagement] || opts[:engagement_id] ? load_records(opts) : load_all_records
        row = rows.find { |item| item[:label] == label }
        return nil unless row

        decrypt_secret(row: row[:secret] || row)
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
          row.merge(secret: fetch(label: row[:label], engagement: row[:engagement]))
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
        text.gsub(/\{\{vault:([^}]+)\}\}/) { fetch(label: Regexp.last_match(1).to_s.strip).to_s }
      end

      public_class_method def self.redact(opts = {})
        text = opts[:text].to_s
        load_all_records.each do |row|
          val = decrypt_secret(row: row[:secret] || row).to_s
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

        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.decrypt
        cipher.key = master_key
        cipher.iv = Base64.strict_decode64(row[:iv] || row['iv'].to_s)
        cipher.auth_tag = Base64.strict_decode64(row[:tag] || row['tag'].to_s)
        cipher.auth_data = 'pwn-vault'
        cipher.update(Base64.strict_decode64(row[:ct] || row['ct'].to_s)) + cipher.final
      rescue StandardError
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
        return [] unless File.file?(path)

        data = JSON.parse(File.read(path), symbolize_names: true)
        if data.is_a?(Hash) && data[:records].is_a?(Array)
          data[:records].map { |row| row.transform_keys(&:to_sym) }
        elsif data.is_a?(Hash)
          data.map do |label, row|
            next unless row.is_a?(Hash)

            { label: label.to_s, secret: row.transform_keys(&:to_sym), engagement: 'default', host: '', source: 'legacy' }
          end.compact
        else
          []
        end
      rescue StandardError
        []
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
            passphrase: 'optional - required unless keyring is supplied',
            keyring: 'optional - callable OS keyring reader returning a raw 32-byte key',
            key_id: 'optional - keyring identifier, default pwn-ai-credentials'
          )
          # Open an authenticated envelope in memory; never writes plaintext.
          #{self}.open_credentials(
            envelope: 'required - sealed credentials hash',
            passphrase: 'optional - required for passphrase envelopes',
            keyring: 'optional - callable OS keyring reader for keyring envelopes'
          )
          # Run refresh encryption secrets and return its result
          #{self}.refresh_encryption_secrets(
            file: 'required - file to encrypt with new key and iv',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt'
          )

          # Run create and return its result
          #{self}.create(
            file: 'required - encrypted file to create',
            decryptor_file: 'optional - file to save the key && iv values'
          )

          # Run decrypt and return its result
          #{self}.decrypt(
            file: 'required - file to decrypt',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt'
          )

          # Run dump and return its result
          #{self}.dump(
            file: 'required - file to dump',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt',
            yaml: 'optional - dump as parsed yaml hash (default: true)'
          )

          # Run edit and return its result
          #{self}.edit(
            file: 'required - file to edit',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt',
            editor: 'optional - editor to use (default: /usr/bin/vim)'
          )

          # Run encrypt and return its result
          #{self}.encrypt(
            file: 'required - file to encrypt',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt'
          )

          # Run file encrypted and return its result
          #{self}.file_encrypted?(
            file: 'required - file to check if encrypted'
          )

          # Store a secret outside the transcript (AES-GCM; key in ~/.pwn-vault.key).
          #{self}.store(
            secret: 'required - secret value (password, token, or key material)',
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
            text: 'required - string possibly containing {{vault:label}} tokens'
          )

          # Replace stored secret values with {{vault:label}} placeholders.
          #{self}.redact(
            text: 'required - string that may contain stored secrets'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
