# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'yaml'

module PWN
  module Plugins
    # Used to encrypt/decrypt configuration files leveraging AES256
    module Vault
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

      def self.dump(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        key = opts[:key] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'Key'
        )

        iv = opts[:iv] ||= PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: 'IV'
        )

        yaml = opts[:yaml] ||= true

        decrypt(
          file: file,
          key: key,
          iv: iv
        )

        if yaml
          file_dump = YAML.load_file(file, symbolize_names: true)
        else
          file_dump = File.read(file)
        end

        encrypt(
          file: file,
          key: key,
          iv: iv
        )

        file_dump
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

      def self.edit(opts = {})
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

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.refresh_encryption_secrets(
            file: 'required - file to encrypt with new key and iv',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt'
          )

          #{self}.create(
            file: 'required - file to encrypt',
            decryptor_file: 'optional - file to save the key && iv values'
          )

          #{self}.decrypt(
            file: 'required - file to decrypt',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt'
          )

          #{self}.dump(
            file: 'required - file to dump',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt',
        #   search: 'optional - search for a specific string'
          )

          #{self}.edit(
            file: 'required - file to edit',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt',
            editor: 'optional - editor to use (default: \"/usr/bin/vim\")'
          )

          #{self}.encrypt(
            file: 'required - file to encrypt',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt'
          )

          #{self}.file_encrypted?(
            file: 'required - file to check if encrypted'
          )

          #{self}.authors
        "
      end
    end
  end
end
