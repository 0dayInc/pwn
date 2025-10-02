# frozen_string_literal: true

require 'json'
require 'rest-client'
require 'tty-spinner'

module PWN
  module Blockchain
    # This plugin interacts with BitCoin's Blockchain API.
    module ETH
      # Supported Method Parameters::
      # eth_rest_call(
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST',
      #   timeout: 'optional timeout in seconds (defaults to 180)',
      #   spinner: 'optional - display spinner (defaults to false)'
      # )

      private_class_method def self.eth_rest_call(opts = {})
        http_method = if opts[:http_method].nil?
                        :get
                      else
                        opts[:http_method].to_s.scrub.to_sym
                      end

        base_uri = 'https://api.blockcypher.com/v1/eth/'
        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]
        headers = { content_type: 'application/json; charset=UTF-8' }

        http_body = opts[:http_body]
        http_body ||= {}

        timeout = opts[:timeout]
        timeout ||= 180

        spinner = opts[:spinner] || false

        browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_client = browser_obj[:browser]::Request

        if spinner
          spin = TTY::Spinner.new(format: :dots)
          spin.auto_spin
        end

        retries = 0
        case http_method
        when :delete, :get
          headers[:params] = params
          response = rest_client.execute(
            method: http_method,
            url: "#{base_uri}#{rest_call}",
            headers: headers,
            verify_ssl: false,
            timeout: timeout
          )

        when :post
          if http_body.key?(:multipart)
            headers[:content_type] = 'multipart/form-data'

            response = rest_client.execute(
              method: http_method,
              url: "#{base_uri}#{rest_call}",
              headers: headers,
              payload: http_body,
              verify_ssl: false,
              timeout: timeout
            )
          else
            response = rest_client.execute(
              method: http_method,
              url: "#{base_uri}#{rest_call}",
              headers: headers,
              payload: http_body.to_json,
              verify_ssl: false,
              timeout: timeout
            )
          end

        else
          raise "Unsupported HTTP Method #{http_method} for #{self} Plugin"
        end

        response
      rescue RestClient::ExceptionWithResponse => e
        case e.http_code
        when 400, 404
          "#{e.http_code} #{e.message}: #{e.response.body}"
        else
          raise e
        end
      rescue StandardError => e
        raise e
      ensure
        spin.stop if spinner
      end

      # Supported Method Parameters::
      # latest_block = PWN::Blockchain::ETH.get_latest_block(
      #   token: 'optional - API token for higher rate limits'
      # )

      public_class_method def self.get_latest_block(opts = {})
        params = {}
        params[:token] = opts[:token] if opts[:token]

        rest_call = 'main'
        response = eth_rest_call(rest_call: rest_call, params: params)

        JSON.parse(response.body, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Blockchain::ETH.get_block_details(
      #   height: 'required - block height number',
      #   token: 'optional - API token for higher rate limits'
      # )
      public_class_method def self.get_block_details(opts = {})
        height = opts[:height]
        params = {}
        params[:token] = opts[:token] if opts[:token]

        rest_call = "main/blocks/#{height}"
        response = eth_rest_call(rest_call: rest_call, params: params)

        JSON.parse(response.body, symbolize_names: true)
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
          latest_block = #{self}.get_latest_block

          block_details = #{self}.get_block_details(
            height: 'required - block height number'
          )

          #{self}.authors
        "
      end
    end
  end
end
