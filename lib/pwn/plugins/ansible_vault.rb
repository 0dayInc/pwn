# frozen_string_literal: true

require 'yaml'
module PWN
  module Plugins
    # Used to encrypt/decrypt configuration files leveraging AES256
    # (ansible-vault utility wrapper)
    module AnsibleVault
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::Plugins::AnsibleVault.encrypt(
      #   yaml_config: 'required - yaml config to encrypt',
      #   vpassfile: 'required - path to anisble-vault pass file'
      # )

      public_class_method def self.encrypt(opts = {})
        yaml_config = opts[:yaml_config].to_s.scrub if File.exist?(opts[:yaml_config].to_s.scrub)
        vpassfile = opts[:vpassfile].to_s.scrub if File.exist?(opts[:vpassfile].to_s.scrub)

        `sudo ansible-vault encrypt #{yaml_config} --vault-password-file #{vpassfile}`
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::AnsibleVault.decrypt(
      #   yaml_config: 'required - yaml config to decrypt',
      #   vpassfile: 'required - path to anisble-vault pass file'
      # )

      public_class_method def self.decrypt(opts = {})
        yaml_config = opts[:yaml_config].to_s.scrub if File.exist?(opts[:yaml_config].to_s.scrub)
        vpassfile = opts[:vpassfile].to_s.scrub if File.exist?(opts[:vpassfile].to_s.scrub)

        if File.extname(yaml_config) == '.yaml'
          config_resp = YAML.safe_load(`sudo ansible-vault view #{yaml_config} --vault-password-file #{vpassfile}`)
        else
          config_resp = `sudo ansible-vault view #{yaml_config} --vault-password-file #{vpassfile}`
        end

        config_resp
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:

          #{self}.encrypt(
            yaml_config: 'required - yaml config to encrypt',
            vpassfile: 'required - path to anisble-vault pass file'
          )

          #{self}.decrypt(
            yaml_config: 'required - yaml config to decrypt',
            vpassfile: 'required - path to anisble-vault pass file'
          )

          #{self}.authors
        "
      end
    end
  end
end
