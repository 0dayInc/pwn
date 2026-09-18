# frozen_string_literal: true

require 'base64'

module PWN
  module Plugins
    # This plugin Base64 encodes/decodes AuthN credentials for passing to a ''Basic''
    # authorization HTTP header.
    module BasicAuth
      # Supported Method Parameters::
      # PWN::Plugins::BasicAuth.encode(
      #   username: 'optional username',
      #   password: 'optional password'
      # )

      public_class_method def self.encode(opts = {})
        basic_user = opts[:username]
        basic_pass = opts[:password]
        if (basic_user.nil? || basic_pass.nil?) && !opts[:host].to_s.empty?
          hit = Array(PWN::Plugins::Vault.offer(host: opts[:host], service: opts[:service], engagement: opts[:engagement] || opts[:engagement_id])).first
          if hit
            basic_user = hit[:username] if basic_user.nil?
            basic_pass = hit[:secret] if basic_pass.nil?
          end
        end
        basic_user = basic_user.to_s.chomp unless basic_user.nil?
        basic_pass = basic_pass.to_s.chomp unless basic_pass.nil?
        base64_str = "#{basic_user}:#{basic_pass}"
        @base64_encoded_auth = Base64.strict_encode64(base64_str).to_s.chomp
        @base64_encoded_auth
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BasicAuth.decode(
      #   base64_str: 'required base64 encoded string'
      # )

      public_class_method def self.decode(opts = {})
        base64_str = opts[:base64_str]
        @base64_decoded_auth = Base64.decode64(base64_str)
        @base64_decoded_auth
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
          # Run encode and return its result
          #{self}.encode(
            username: 'optional - username; omitted values are filled from Vault.offer',
            password: 'optional - password; omitted values are filled from Vault.offer',
            host: 'optional - hostname used to offer recon loot when username or password is omitted',
            service: 'optional - service name such as http or ssh used to match loot',
            engagement: 'optional - engagement id scoping the loot file (defaults to default)',
            engagement_id: 'optional - alias for engagement'
          )

          # Run decode and return its result
          #{self}.decode(
            base64_str: 'required - required base64 encoded string'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
