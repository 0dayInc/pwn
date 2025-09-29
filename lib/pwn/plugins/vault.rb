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

      def self.refresh_encryption_secrets(opts = {})
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
        Pry.config.refresh_config = true if defined?(Pry)

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

      # Supported Method Parameters::
      # PWN::Plugins::Vault.refresh_config_for_repl(
      #    yaml_config_path: 'required - full path to pwn.yaml file',
      #    pi: 'optional - Pry instance (default: Pry)',
      #    decryption_file: 'optional - full path to decryption YAML file'
      #  )
      public_class_method def self.refresh_config_for_repl(opts = {})
        yaml_config_path = opts[:yaml_config_path]

        return false unless File.exist?(yaml_config_path)

        pi = opts[:pi] ||= Pry

        is_encrypted = PWN::Plugins::Vault.file_encrypted?(file: yaml_config_path)

        if is_encrypted
          # TODO: Implement "something you know, something you have, && something you are?"
          decryption_file = opts[:decryption_file] ||= "#{Dir.home}/pwn.decryptor.yaml"
          raise "ERROR: #{decryption_file} does not exist." unless File.exist?(decryption_file)

          yaml_decryptor = YAML.load_file(decryption_file, symbolize_names: true)

          key = opts[:key] ||= yaml_decryptor[:key] ||= ENV.fetch('PWN_DECRYPTOR_KEY')
          key = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Decryption Key') if key.nil?

          iv = opts[:iv] ||= yaml_decryptor[:iv] ||= ENV.fetch('PWN_DECRYPTOR_IV')
          iv = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Decryption IV') if iv.nil?

          yaml_config = PWN::Plugins::Vault.dump(
            file: yaml_config_path,
            key: key,
            iv: iv
          )
        else
          yaml_config = YAML.load_file(yaml_config_path, symbolize_names: true)
        end
        pi.config.p = yaml_config
        Pry.config.p = yaml_config

        valid_ai_engines = %i[
          grok
          openai
          ollama
        ]
        ai_engine = yaml_config[:ai_engine].to_s.downcase.to_sym

        raise "ERROR: Unsupported AI Engine: #{ai_engine} in #{yaml_config_path}.  Supported AI Engines:\n#{valid_ai_engines.inspect}" unless valid_ai_engines.include?(ai_engine)

        pi.config.pwn_ai_engine = ai_engine
        Pry.config.pwn_ai_engine = ai_engine

        pi.config.pwn_ai_base_uri = pi.config.p[ai_engine][:base_uri]
        Pry.config.pwn_ai_base_uri = pi.config.pwn_ai_base_uri

        pi.config.pwn_ai_key = pi.config.p[ai_engine][:key]
        Pry.config.pwn_ai_key = pi.config.pwn_ai_key

        pi.config.pwn_ai_model = pi.config.p[ai_engine][:model]
        Pry.config.pwn_ai_model = pi.config.pwn_ai_model

        pi.config.pwn_ai_system_role_content = pi.config.p[ai_engine][:system_role_content]
        Pry.config.pwn_ai_system_role_content = pi.config.pwn_ai_system_role_content

        pi.config.pwn_ai_temp = pi.config.p[ai_engine][:temp]
        Pry.config.pwn_ai_temp = pi.config.pwn_ai_temp

        pi.config.pwn_asm_arch = pi.config.p[:asm][:arch]
        Pry.config.pwn_asm_arch = pi.config.pwn_asm_arch

        pi.config.pwn_asm_endian = pi.config.p[:asm][:endian]
        Pry.config.pwn_asm_endian = pi.config.pwn_asm_endian

        pi.config.pwn_irc = pi.config.p[:irc]
        Pry.config.pwn_irc = pi.config.pwn_irc

        pi.config.pwn_hunter = pi.config.p[:hunter][:api_key]
        Pry.config.pwn_hunter = pi.config.pwn_hunter

        pi.config.pwn_shodan = pi.config.p[:shodan][:api_key]
        Pry.config.pwn_shodan = pi.config.pwn_shodan

        Pry.config.refresh_config = false

        true
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
            file: 'required - file to encrypt'
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

          #{self}.refresh_config_for_repl(
            yaml_config_path: 'required - full path to pwn.yaml file',
            pi: 'optional - Pry instance (default: Pry)',
            decryption_file: 'optional - full path to decryption YAML file'
          )

          #{self}.authors
        "
      end
    end
  end
end
