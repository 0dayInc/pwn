# frozen_string_literal: true

require 'fileutils'
require 'yaml'

module PWN
  # Used to manage PWN configuration settings within PWN drivers.
  module Config
    # Supported Method Parameters::
    # PWN::Config.refresh_env(
    #   pwn_env_path: 'optional - Path to pwn.yaml file.  Defaults to ~/.pwn/pwn.yaml',
    #   pwn_dec_path: 'optional - Path to pwn.decryptor.yaml file.  Defaults to ~/.pwn/pwn.decryptor.yaml'
    # )

    public_class_method def self.refresh_env(opts = {})
      pwn_env_root = "#{Dir.home}/.pwn"
      FileUtils.mkdir_p(pwn_env_root)

      pwn_env_path = opts[:pwn_env_path] ||= "#{pwn_env_root}/pwn.yaml"
      return {} unless File.exist?(pwn_env_path)

      is_encrypted = PWN::Plugins::Vault.file_encrypted?(file: pwn_env_path)

      if is_encrypted
        pwn_dec_path = opts[:pwn_dec_path] ||= "#{pwn_env_root}/pwn.decryptor.yaml"
        raise "PWN Decryptor (#{pwn_dec_path}) does not exist!" unless File.exist?(pwn_dec_path)

        pwn_decryptor = YAML.load_file(pwn_dec_path, symbolize_names: true)

        key = opts[:key] ||= pwn_decryptor[:key] ||= ENV.fetch('PWN_DECRYPTOR_KEY')
        key = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Decryption Key') if key.nil?

        iv = opts[:iv] ||= pwn_decryptor[:iv] ||= ENV.fetch('PWN_DECRYPTOR_IV')
        iv = PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Decryption IV') if iv.nil?

        env = PWN::Plugins::Vault.dump(
          file: pwn_env_path,
          key: key,
          iv: iv
        )
      else
        env = YAML.load_file(pwn_env_path, symbolize_names: true)
      end

      valid_ai_engines = PWN::AI.help.reject { |e| e.downcase == :introspection }.map(&:downcase)

      engine = env[:ai][:active].to_s.downcase.to_sym
      raise "ERROR: Unsupported AI Engine: #{engine} in #{pwn_env_path}.  Supported AI Engines:\n#{valid_ai_engines.inspect}" unless valid_ai_engines.include?(engine)

      key = env[:ai][engine][:key]
      if key.nil?
        key = PWN::Plugins::AuthenticationHelper.mask_password(
          prompt: "#{engine} API Key"
        )
        env[:ai][engine][:key] = key
      end

      model = env[:ai][engine][:model]
      system_role_content = env[:ai][engine][:system_role_content]

      # Reset the ai response history on env refresh
      env[:ai][engine][:response_history] = {
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
      env[:pwn_env_path] = pwn_env_path
      env[:pwn_dec_path] = pwn_dec_path if is_encrypted

      Pry.config.refresh = false if defined?(Pry)

      PWN.send(:remove_const, :Env) if PWN.const_defined?(:Env)
      PWN.const_set(:Env, env.freeze)
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
        #{self}.refresh_env(
          pwn_env_path: 'optional - Path to pwn.yaml file.  Defaults to ~/.pwn/pwn.yaml',
          pwn_dec_path: 'optional - Path to pwn.decryptor.yaml file.  Defaults to ~/.pwn/pwn.decryptor.yaml'
        )

        #{self}.authors
      "
    end
  end
end
