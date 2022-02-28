# frozen_string_literal: true

require 'slack-ruby-client'

module PWN
  module Plugins
    # This plugin is used for interacting w/ Slack over the Web API.
    module SlackClient
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # PWN::Plugins::SlackClient.login(
      #   api_token: 'required slack api token'
      # )

      public_class_method def self.login(opts = {})
        api_token = opts[:api_token]

        if opts[:api_token].nil?
          api_token = PWN::Plugins::AuthenticationHelper.mask_password
        else
          api_token = opts[:api_token].to_s.scrub
        end

        @@logger.info('Logging into Slack...')
        slack_obj = Slack::Web::Client.new
        slack_obj.token = api_token
        slack_obj.auth_test

        slack_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::SlackClient.post_message(
      #   slack_obj: 'required slack_obj returned from login method',
      #   channel: 'required #channel to post message',
      #   message: 'required message to post'
      # )

      public_class_method def self.post_message(opts = {})
        slack_obj = opts[:slack_obj]
        channel = opts[:channel].to_s.scrub
        message = opts[:message].to_s.scrub

        slack_obj.chat_postMessage(
          channel: channel,
          text: message,
          as_user: true
        )

        slack_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::SlackClient.logout(
      #   slack_obj: 'required slack_obj returned from login method'
      # )

      public_class_method def self.logout(opts = {})
        slack_obj = opts[:slack_obj]
        @@logger.info('Logging out...')
        slack_obj.token = nil
        slack_obj = nil
        @@logger.info('Complete.')
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
          slack_obj = #{self}.login(
            api_token: 'optional slack api token (will prompt if blank)'
          )

          #{self}.post_message(
            slack_obj: 'required slack_obj returned from login method',
            channel: 'required #channel to post message',
            message: 'required message to post'
          )

          #{self}.logout(
            slack_obj: 'required slack_obj returned from login method'
          )

          #{self}.authors
        "
      end
    end
  end
end
