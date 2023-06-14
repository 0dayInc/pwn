# frozen_string_literal: true

require 'json'
require 'securerandom'
require 'tty-spinner'

module PWN
  module Plugins
    # This plugin is used for interacting w/ the Black Duck Binary Analysis
    # REST API using the 'rest' browser type of PWN::Plugins::TransparentBrowser.
    # This is based on the following Black Duck Binary Analysis API Specification:
    # https://protecode-sc.com/help/api
    module BlackDuckBinaryAnalysis
      # Supported Method Parameters::
      # bd_bin_analysis_rest_call(
      #   token: 'required - Black Duck Binary Analysis API token',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.bd_bin_analysis_rest_call(opts = {})
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        http_body = opts[:http_body]
        http_body ||= {}
        base_bd_bin_analysis_api_uri = 'https://protocode-sc.com/api'
        token = opts[:token]

        content_type = 'application/json; charset=UTF-8'

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

        spinner = TTY::Spinner.new
        spinner.auto_spin

        case http_method
        when :delete
          response = rest_client.execute(
            method: :delete,
            url: "#{base_bd_bin_analysis_api_uri}/#{rest_call}",
            headers: {
              content_type: content_type,
              authorization: "Bearer #{token}",
              params: params
            },
            verify_ssl: false
          )

        when :get
          response = rest_client.execute(
            method: :get,
            url: "#{base_bd_bin_analysis_api_uri}/#{rest_call}",
            headers: {
              content_type: content_type,
              authorization: "Bearer #{token}",
              params: params
            },
            verify_ssl: false
          )

        when :post
          if http_body.key?(:multipart)
            response = rest_client.execute(
              method: :post,
              url: "#{base_bd_bin_analysis_api_uri}/#{rest_call}",
              headers: {
                authorization: "Bearer #{token}"
              },
              payload: http_body,
              verify_ssl: false
            )
          else
            response = rest_client.execute(
              method: :post,
              url: "#{base_bd_bin_analysis_api_uri}/#{rest_call}",
              headers: {
                content_type: content_type,
                authorization: "Bearer #{token}"
              },
              payload: http_body.to_json,
              verify_ssl: false
            )
          end

        when :put
          if http_body.key?(:multipart)
            response = rest_client.execute(
              method: :put,
              url: "#{base_bd_bin_analysis_api_uri}/#{rest_call}",
              headers: {
                authorization: "Bearer #{token}"
              },
              payload: http_body,
              verify_ssl: false
            )
          else
            response = rest_client.execute(
              method: :post,
              url: "#{base_bd_bin_analysis_api_uri}/#{rest_call}",
              headers: {
                content_type: content_type,
                authorization: "Bearer #{token}"
              },
              payload: http_body.to_json,
              verify_ssl: false
            )
          end

        else
          raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end
        response
      rescue StandardError => e
        case e.message
        when '400 Bad Request', '404 Resource Not Found'
          "#{e.message}: #{e.response}"
        else
          raise e
        end
      ensure
        spinner.stop
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.get_groups(
      #   token: 'required - Bearer token'
      # )

      public_class_method def self.get_groups(opts = {})
        token = opts[:token]

        response = bd_bin_analysis_rest_call(
          token: token,
          rest_call: 'groups'
        )

        JSON.parse(response, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # response = PWN::Plugins::BlackDuckBinaryAnalysis.upload_file(
      #   token: 'required - Bearer token',
      #   file: 'required - file to upload',
      #   purpose: 'optional - intended purpose of the uploaded documents (defaults to fine-tune'
      # )

      public_class_method def self.upload_file(opts = {})
        token = opts[:token]
        file = opts[:file]
        raise "ERROR: #{file} not found." unless File.exist?(file)

        purpose = opts[:purpose]
        purpose ||= 'fine-tune'

        http_body = {
          multipart: true,
          file: File.new(file, 'rb'),
          purpose: purpose
        }

        response = bd_bin_analysis_rest_call(
          http_method: :post,
          token: token,
          rest_call: 'files',
          http_body: http_body
        )

        JSON.parse(response, symbolize_names: true)
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
          response = #{self}.get_groups(
            token: 'required - Bearer token'
          )

          response = #{self}.upload_file(
            token: 'required - Black Duck Binary Analysis API token',
            file: 'required - file to upload'
          )

          #{self}.authors
        "
      end
    end
  end
end
