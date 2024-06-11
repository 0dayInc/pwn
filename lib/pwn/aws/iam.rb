# frozen_string_literal: true

require 'aws-sdk'
require 'base32'
require 'base64'

module PWN
  module AWS
    # This module provides a client for making API requests to AWS Identity and Access Management.
    module IAM
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::AWS::IAM.connect(
      #   region: 'required - region name to connect (eu-west-1, ap-southeast-1, ap-southeast-2, eu-central-1, ap-northeast-2, ap-northeast-1, us-east-1, sa-east-1, us-west-1, us-west-2)',
      #   access_key_id: 'required - Use AWS STS for best privacy (i.e. temporary access key id)',
      #   secret_access_key: 'required - Use AWS STS for best privacy (i.e. temporary secret access key',
      #   sts_session_token: 'optional - Temporary token returned by STS client for best privacy'
      # )

      public_class_method def self.connect(opts = {})
        region = opts[:region].to_s.scrub.chomp.strip
        access_key_id = opts[:access_key_id].to_s.scrub.chomp.strip
        secret_access_key = opts[:secret_access_key].to_s.scrub.chomp.strip
        sts_session_token = opts[:sts_session_token].to_s.scrub.chomp.strip

        @@logger.info('Connecting to AWS IAM...')
        if sts_session_token == ''
          iam_obj = Aws::IAM::Client.new(
            region: region,
            access_key_id: access_key_id,
            secret_access_key: secret_access_key
          )
        else
          iam_obj = Aws::IAM::Client.new(
            region: region,
            access_key_id: access_key_id,
            secret_access_key: secret_access_key,
            session_token: sts_session_token
          )
        end
        @@logger.info("complete.\n")

        iam_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::AWS::IAM.decode_key(
      #   key: 'required - key to decode',
      #   key_type: 'optional - key type :access_key_id|:secret_access_key|:sts_session_token (Default: access_key_id)',
      # )
      public_class_method def self.decode_key(opts = {})
        key = opts[:key].to_s.scrub.chomp.strip.upcase
        raise 'ERROR: Key is required' if key == ''

        key_type = opts[:key_type] || :access_key_id
        key_type = key_type.to_s.scrub.chomp.strip.to_sym

        decoded_key = {}

        prefix = key[0..3].to_s.downcase.to_sym
        case prefix
        when :abia
          resource_type = 'AWS STS Service Bearer Token'
          decoded_key[:prefix] = prefix
        when :acca
          resource_type = 'Context Specific Credential'
          decoded_key[:prefix] = prefix
        when :agpa
          resource_type = 'Group'
          decoded_key[:prefix] = prefix
        when :aida
          resource_type = 'IAM User'
          decoded_key[:prefix] = prefix
        when :aipa
          resource_type = 'EC2 Instance Profile'
          decoded_key[:prefix] = prefix
        when :akia
          resource_type = 'Access Key'
          decoded_key[:prefix] = prefix
        when :anpa
          resource_type = 'Managed Policy'
          decoded_key[:prefix] = prefix
        when :anva
          resource_type = 'Version in a Managed Policy'
          decoded_key[:prefix] = prefix
        when :apka
          resource_type = 'Public Key'
          decoded_key[:prefix] = prefix
        when :aroa
          resource_type = 'Role'
          decoded_key[:prefix] = prefix
        when :asca
          resource_type = 'Certificate'
          decoded_key[:prefix] = prefix
        when :asia
          resource_type = 'Temporary (AWS STS) Keys'
          decoded_key[:prefix] = prefix
        else
          resource_type = 'Secret Access Key' if key_type == :secret_access_key
          resource_type = 'STS Session' if key_type == :sts_session_token
        end

        decoded_key[:resource_type] = resource_type

        case key_type
        when :access_key_id
          suffix = key[4..-1]
          decoded_suffix = Base32.decode(suffix)
          trimmed_decoded_suffix = decoded_suffix[0..5]
          z = trimmed_decoded_suffix.bytes.inject { |total, byte| (total << 8) + byte }
          mask = 0x7FFFFFFFFF80
          key = (z & mask) >> 7
          decoded_key[:account_id] = key
        when :secret_access_key, :sts_session_token
          decoded_key[:decoded_key] = Base64.strict_decode64(key)
        else
          raise "ERROR: Invalid Key Type: #{key_type}.  Valid key types are :access_key_id|:secret_access_key|:sts_session_token"
        end
        decoded_key[:key_type] = key_type

        decoded_key
      rescue StandardError => e
        raise e
      end

      # TODO: Implement this method
      # Supported Method Parameters::
      # PWN::AWS::IAM.generate_access_key(
      #   account_id: 'required - AWS Account ID',
      #   prefix: 'optional - prefix for the key :abia|:acca|:agpa|:aida|:aipa|:akia|:anpa|:anva|:apka|:aroa|:asca|:asia (Default: akia)'
      # )
      # public_class_method def self.generate_access_key(opts = {})
      #   account_id = opts[:account_id].to_i
      #   raise 'ERROR: Account ID is required and must be an Integer' unless account_id.positive?

      #   prefix = opts[:prefix] ||= :akia
      #   prefix_str = prefix.to_s.scrub.chomp.strip.upcase

      #   mask = 0x7FFFFFFFFF80
      #   key = (account_id & mask) << 7

      #   "#{prefix_str}#{encoded_key}"
      # rescue StandardError => e
      #   raise e
      # end

      # Supported Method Parameters::
      # PWN::AWS::IAM.disconnect(
      #   iam_obj: 'required - iam_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        iam_obj = opts[:iam_obj]
        @@logger.info('Disconnecting...')
        iam_obj = nil
        @@logger.info("complete.\n")

        iam_obj
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
          iam_obj = #{self}.connect(
            region: 'required - region name to connect (eu-west-1, ap-southeast-1, ap-southeast-2, eu-central-1, ap-northeast-2, ap-northeast-1, us-east-1, sa-east-1, us-west-1, us-west-2)',
            access_key_id: 'required - Use AWS STS for best privacy (i.e. temporary access key id)',
            secret_access_key: 'required - Use AWS STS for best privacy (i.e. temporary secret access key',
            sts_session_token: 'optional - Temporary token returned by STS client for best privacy'
          )
          puts iam_obj.public_methods

          decoded_key = #{self}.decode_key(
            key: 'required - key to decode',
            key_type: 'optional - key type :access_key_id|:secret_access_key|:sts_session_token (Default: access_key_id
          )

          #{self}.disconnect(
            iam_obj: 'required - iam_obj returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
