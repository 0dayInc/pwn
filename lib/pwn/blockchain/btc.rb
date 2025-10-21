# frozen_string_literal: true

require 'base64'
require 'json'
require 'rest-client'
require 'tty-spinner'
require 'date'

module PWN
  module Blockchain
    # This plugin interacts with BitCoin's Blockchain API.
    module BTC
      # Supported Method Parameters::
      # btc_rest_call(
      #   http_method: 'optional HTTP method (defaults to GET)
      #   rest_call: 'required rest call to make per the schema',
      #   params: 'optional params passed in the URI or HTTP Headers',
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST',
      #   timeout: 'optional timeout in seconds (defaults to 180)',
      #   spinner: 'optional - display spinner (defaults to false)'
      # )

      private_class_method def self.btc_rest_call(opts = {})
        blockchain = PWN::Env[:plugins][:blockchain][:bitcoin]
        raise 'ERROR: Jira Server Hash not found in PWN::Env.  Run i`pwn -Y default.yaml`, then `PWN::Env` for usage.' if blockchain.nil?

        rpc_host = blockchain[:rpc_host] ||= '127.0.0.1'
        rpc_port = blockchain[:rpc_port] ||= '8332'
        base_uri = "http://#{rpc_host}:#{rpc_port}"

        rpc_user = blockchain[:rpc_user] ||= PWN::Plugins::AuthenticationHelper.username(prompt: 'Bitcoin Node RPC Username')
        rpc_pass = blockchain[:rpc_pass] ||= PWN::Plugins::AuthenticationHelper.mask_password(prompt: 'Bitcoin Node RPC Password')

        http_method = opts[:http_method] ||= :get

        rest_call = opts[:rest_call].to_s.scrub
        params = opts[:params]

        basic_auth = Base64.strict_encode64("#{rpc_user}:#{rpc_pass}")

        headers = {
          content_type: 'application/json; charset=UTF-8',
          authorization: "Basic #{basic_auth}"
        }

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
        case http_method.to_s.scrub.downcase.to_sym
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

      private_class_method def self.btc_rpc_call(method:, params: [])
        http_body = {
          jsonrpc: '1.0',
          id: self,
          method: method,
          params: params
        }

        response = btc_rest_call(
          http_method: :post,
          http_body: http_body
        )

        res = JSON.parse(response.body, symbolize_names: true)
        raise "RPC Error: #{res[:error][:code]} - #{res[:error][:message]}" if res[:error]

        res
      rescue StandardError => e
        raise e
      end

      private_class_method def self.get_block_timestamp(height)
        res = btc_rpc_call(method: 'getblockhash', params: [height])
        block_hash = res[:result]

        res = btc_rpc_call(method: 'getblockheader', params: [block_hash])
        res[:result][:time]
      end

      private_class_method def self.find_first_block_ge_timestamp(target_ts)
        chain_info = get_latest_block[:result]
        low = 0
        high = chain_info[:blocks]
        result = nil
        while low <= high
          mid = (low + high) / 2
          ts = get_block_timestamp(mid)
          if ts >= target_ts
            result = mid
            high = mid - 1
          else
            low = mid + 1
          end
        end
        result
      end

      private_class_method def self.find_last_block_le_timestamp(target_ts)
        chain_info = get_latest_block[:result]
        low = 0
        high = chain_info[:blocks]
        result = nil
        while low <= high
          mid = (low + high) / 2
          ts = get_block_timestamp(mid)
          if ts <= target_ts
            result = mid
            low = mid + 1
          else
            high = mid - 1
          end
        end
        result
      end

      # Supported Method Parameters::
      # latest_block = PWN::Blockchain::BTC.get_latest_block

      public_class_method def self.get_latest_block
        latest_block = btc_rpc_call(method: 'getblockchaininfo', params: [])
        system_role_content = 'Provide a useful summary of this latest bitcoin block returned from a bitcoin node via getblockchaininfo.'
        ai_analysis = PWN::AI::Introspection.reflect_on(
          request: latest_block.to_s,
          system_role_content: system_role_content
        )
        puts ai_analysis

        latest_block
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Blockchain::BTC.get_block_details(
      #   height: 'required - block height as an integer (0 for genesis block / Defaults to latest block)'
      # )

      public_class_method def self.get_block_details(opts = {})
        latest_block = get_latest_block[:result][:blocks]
        height = opts[:height] ||= latest_block

        raise "ERROR: height must be >= 0 && <= #{latest_block}" if height.negative? || height > latest_block

        hash_res = btc_rpc_call(method: 'getblockhash', params: [height])
        block_hash = hash_res[:result]

        # Verbosity 1: block details with tx IDs
        block_res = btc_rpc_call(method: 'getblock', params: [block_hash, 1])

        block_res[:result]
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # transactions = PWN::Blockchain::BTC.get_transactions(
      #   from: 'required - start date in YYYY-MM-DD format',
      #   to: 'required - end date in YYYY-MM-DD format'
      # )

      public_class_method def self.get_transactions(opts = {})
        from_date = opts[:from]
        to_date = opts[:to]

        raise ArgumentError, 'from and to dates are required' if from_date.nil? || to_date.nil?

        start_ts = Date.parse(from_date).to_time.to_i
        end_ts = Date.parse(to_date).to_time.to_i + 86_399 # Include the entire end day

        start_height = find_first_block_ge_timestamp(start_ts)
        end_height = find_last_block_le_timestamp(end_ts)

        txs = []
        if start_height && end_height && start_height <= end_height
          (start_height..end_height).each do |height|
            block_hash_res = btc_rpc_call(method: 'getblockhash', params: [height])
            block_hash = block_hash_res[:result]

            block_res = btc_rpc_call(method: 'getblock', params: [block_hash, 1])
            txs.concat(block_res[:result][:tx])
          end
        end

        txs
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
            height: 'required - block height as an integer (0 for genesis block / Defaults to latest block)'
          )

          transactions = #{self}.get_transactions(
            from: 'required - start date in YYYY-MM-DD format',
            to: 'required - end date in YYYY-MM-DD format'
          )

          #{self}.authors
        "
      end
    end
  end
end
