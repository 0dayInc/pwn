# frozen_string_literal: true

require 'aws-sdk'

module PWN
  module AWS
    # This module provides a client for making API requests to Amazon Route 53.
    module Route53
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::AWS::Route53.connect(
      #   region: 'required - region name to connect (eu-west-1, ap-southeast-1, ap-southeast-2, eu-central-1, ap-northeast-2, ap-northeast-1, us-east-1, sa-east-1, us-west-1, us-west-2)',
      #   access_key_id: 'required - AWS Access Key ID',
      #   secret_access_key: 'required - AWS Secret Access Key',
      #   sts_session_token: 'optional - Temporary token returned by STS client for best privacy'
      # )

      public_class_method def self.connect(opts = {})
        region = opts[:region].to_s.scrub.chomp.strip
        access_key_id = opts[:access_key_id].to_s.scrub.chomp.strip
        secret_access_key = opts[:secret_access_key].to_s.scrub.chomp.strip
        sts_session_token = opts[:sts_session_token].to_s.scrub.chomp.strip

        @@logger.info('Logging into AWS Route53...')
        if sts_session_token == ''
          r53_obj = Aws::Route53::Client.new(
            region: region,
            access_key_id: access_key_id,
            secret_access_key: secret_access_key
          )
        else
          r53_obj = Aws::Route53::Client.new(
            region: region,
            access_key_id: access_key_id,
            secret_access_key: secret_access_key,
            session_token: sts_session_token
          )
        end
        @@logger.info("complete.\n")

        r53_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::AWS::Route53.disconnect(
      #   r53_obj: 'required - r53_obj returned from #connect method'
      # )

      public_class_method def self.disconnect(opts = {})
        r53_obj = opts[:r53_obj]
        @@logger.info('Disconnecting from AWS Route53...')
        r53_obj = nil
        @@logger.info("complete.\n")

        r53_obj
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
          r53_obj = #{self}.connect(
            region: 'required - region name to connect (eu-west-1, ap-southeast-1, ap-southeast-2, eu-central-1, ap-northeast-2, ap-northeast-1, us-east-1, sa-east-1, us-west-1, us-west-2)',
            access_key_id: 'required - AWS Access Key ID',
            secret_access_key: 'required - AWS Secret Access Key',
            sts_session_token: 'optional - Temporary token returned by STS client for best privacy'
          )
          puts r53_obj.public_methods

          #{self}.disconnect(
            r53_obj: 'required - r53_obj returned from #connect method'
          )

          #{self}.authors
        "
      end
    end
  end
end
