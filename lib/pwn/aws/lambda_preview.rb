# frozen_string_literal: true

require 'aws-sdk'

module PWN
  module AWS
    # This module provides a client for making API requests to AWS Lambda.
    module LambdaPreview
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::AWS::LambdaPreview.connect(
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

        @@logger.info('Connecting to AWS LambdaPreview...')
        if sts_session_token == ''
          lambda_preview_obj = Aws::LambdaPreview::Client.new(
            region: region,
            access_key_id: access_key_id,
            secret_access_key: secret_access_key
          )
        else
          lambda_preview_obj = Aws::LambdaPreview::Client.new(
            region: region,
            access_key_id: access_key_id,
            secret_access_key: secret_access_key,
            session_token: sts_session_token
          )
        end
        @@logger.info("complete.\n")

        lambda_preview_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::AWS::LambdaPreview.disconnect(
      #   lambda_preview_obj: 'required - lambda_preview_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        lambda_preview_obj = opts[:lambda_preview_obj]
        @@logger.info('Disconnecting...')
        lambda_preview_obj = nil
        @@logger.info("complete.\n")

        lambda_preview_obj
      rescue StandardError => e
        raise e
      end

      # Author(s):: Jacob Hoopes <jake.hoopes@gmail.com>

      public_class_method def self.authors
        "AUTHOR(S):
          Jacob Hoopes <jake.hoopes@gmail.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          lambda_preview_obj = #{self}.connect(
            region: 'required - region name to connect (eu-west-1, ap-southeast-1, ap-southeast-2, eu-central-1, ap-northeast-2, ap-northeast-1, us-east-1, sa-east-1, us-west-1, us-west-2)',
            access_key_id: 'required - Use AWS STS for best privacy (i.e. temporary access key id)',
            secret_access_key: 'required - Use AWS STS for best privacy (i.e. temporary secret access key',
            sts_session_token: 'optional - Temporary token returned by STS client for best privacy'
          )
          puts lambda_preview_obj.public_methods

          #{self}.disconnect(
            lambda_preview_obj: 'required - lambda_preview_obj returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
