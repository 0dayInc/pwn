# frozen_string_literal: true

require 'fileutils'
require 'yaml'

module PWN
  # Used to manage PWN configuration settings within PWN drivers.
  module Config
    # Supported Method Parameters::
    # PWN::Config.refresh(
    #   pwn_config_path: 'optional - Path to pwn.yaml file.  Defaults to ~/.pwn/pwn.yaml',
    #   pwn_decryptor_path: 'optional - Path to pwn.decryptor.yaml file.  Defaults to ~/.pwn/pwn.decryptor.yaml'
    # )

    public_class_method def self.refresh(opts = {})
      pwn_config_root = "#{Dir.home}/.pwn"
      FileUtils.mkdir_p(pwn_config_root)

      pwn_config_path = opts[:pwn_config_path] ||= "#{pwn_config_root}/pwn.yaml"
      return unless File.exist?(pwn_config_path)

      is_encrypted = PWN::Plugins::Vault.file_encrypted?(file: pwn_config_path)

      if is_encrypted
        pwn_decryptor_path = opts[:pwn_decryptor_path] ||= "#{pwn_config_root}/pwn.decryptor.yaml"
        raise "PWN Decryptor (#{pwn_decryptor_path}) does not exist!" unless File.exist?(pwn_decryptor_path)

        pwn_decryptor = YAML.load_file(pwn_decryptor_path, symbolize_names: true)

        key = opts[:key] ||= pwn_decryptor[:key] ||= ENV.fetch('PWN_DECRYPTOR_KEY')
        key = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Decryption Key') if key.nil?

        iv = opts[:iv] ||= pwn_decryptor[:iv] ||= ENV.fetch('PWN_DECRYPTOR_IV')
        iv = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Decryption IV') if iv.nil?

        config = PWN::Plugins::Vault.dump(
          file: pwn_config_path,
          key: key,
          iv: iv
        )
      else
        config = YAML.load_file(pwn_config_path, symbolize_names: true)
      end

      valid_ai_engines = %i[
        grok
        openai
        ollama
      ]

      engine = config[:ai][:active].to_s.downcase.to_sym
      raise "ERROR: Unsupported AI Engine: #{engine} in #{pwn_config_path}.  Supported AI Engines:\n#{valid_ai_engines.inspect}" unless valid_ai_engines.include?(engine)

      model = config[:ai][engine][:model]
      system_role_content = config[:ai][engine][:system_role_content]

      # Reset the ai response history on config refresh
      config[:ai][engine][:response_history] = {
        id: '',
        object: '',
        model: model,
        usage: {},
        choices: [
          {
            role: 'system',
            content: system_role_content
          }
        ]
      }

      # These two lines should be immutable for the session
      config[:pwn_config_path] = pwn_config_path
      config[:pwn_decryptor_path] = pwn_decryptor_path if is_encrypted

      Pry.config.refresh = false if defined?(Pry)

      PWN.send(:remove_const, :CONFIG) if PWN.const_defined?(:CONFIG)
      PWN.const_set(:CONFIG, config)
    end
  end
end
