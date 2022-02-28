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
        basic_user = opts[:username].to_s.chomp unless opts[:username].nil?
        basic_pass = opts[:password].to_s.chomp unless opts[:password].nil?
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

      # Author(s):: 0day Inc <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.encode(
            username: 'optional username',
            password: 'optional password'
          )

          #{self}.decode(base64_str: 'base64 encoded string')

          #{self}.authors
        "
      end
    end
  end
end
