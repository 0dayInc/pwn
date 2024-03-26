# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'yaml'

module PWN
  module Plugins
    # Used to encrypt/decrypt configuration files leveraging AES256
    module Vault
      # Supported Method Parameters::
      # PWN::Plugins::Vault.create(
      #   file: 'required - encrypted file to create'
      # )

      public_class_method def self.create(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)

        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        key = Base64.strict_encode64(cipher.random_key)
        iv = Base64.strict_encode64(cipher.random_iv)

        puts 'Please store the Key && IV in a secure location as they are required for decryption.'
        puts "Key: #{key}"
        puts "IV: #{iv}"

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
      #   file: 'required - file to encrypt',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt'
      # )

      public_class_method def self.decrypt(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        key = opts[:key]
        iv = opts[:iv]

        raise 'ERROR: key and iv parameters are required.' if key.nil? || iv.nil?

        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.decrypt
        cipher.key = Base64.strict_decode64(key)
        cipher.iv = Base64.strict_decode64(iv)

        b64_decoded_file_contents = Base64.strict_decode64(File.read(file))
        plain_text = cipher.update(b64_decoded_file_contents) + cipher.final

        File.write(file, plain_text)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.dump(
      #   file: 'required - file to encrypt',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt'
      # )

      def self.dump(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        key = opts[:key]
        iv = opts[:iv]

        decrypt(
          file: file,
          key: key,
          iv: iv
        )

        puts File.read(file)

        encrypt(
          file: file,
          key: key,
          iv: iv
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Vault.edit(
      #   file: 'required - file to encrypt',
      #   key: 'required - key to decrypt',
      #   iv: 'required - iv to decrypt'
      # )

      def self.edit(opts = {})
        file = opts[:file].to_s.scrub if File.exist?(opts[:file].to_s.scrub)
        key = opts[:key]
        iv = opts[:iv]
        editor = opts[:editor] ||= '/usr/bin/vim'

        decrypt(
          file: file,
          key: key,
          iv: iv
        )

        raise 'ERROR: Editor not found.' unless File.exist?(editor)

        # Get realtive editor in case aliases are used
        relative_editor = File.basename(editor)
        system(relative_editor, file)

        encrypt(
          file: file,
          key: key,
          iv: iv
        )
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
        key = opts[:key]
        iv = opts[:iv]

        raise 'ERROR: key and iv parameters are required.' if key.nil? || iv.nil?

        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.encrypt
        cipher.key = Base64.strict_decode64(key)
        cipher.iv = Base64.strict_decode64(iv)

        data = File.read(file)
        encrypted = cipher.update(data) + cipher.final
        encrypted_string = Base64.strict_encode64(encrypted)

        File.write(file, encrypted_string)
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.create(
            file: 'required - file to encrypt'
          )

          #{self}.decrypt(
            file: 'required - file to encrypt',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt'
          )

          #{self}.dump(
            file: 'required - file to encrypt',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt'
          )

          #{self}.edit(
            file: 'required - file to encrypt',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt'
          )

          #{self}.encrypt(
            file: 'required - file to encrypt',
            key: 'required - key to decrypt',
            iv: 'required - iv to decrypt'
          )

          #{self}.authors
        "
      end
    end
  end
end
