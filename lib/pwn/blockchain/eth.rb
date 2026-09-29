# frozen_string_literal: true

require 'json'
require 'rest-client'
require 'uri'
require 'openssl'
require 'timeout'

module PWN
  module Blockchain
    # Read-only Ethereum intelligence via BlockCypher and explicit JSON-RPC endpoints.
    module ETH
      class RPCError < StandardError; end
      TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'

      # Decode the standard Transfer event layout, not contract conformance.
      # Supported Method Parameters::
      # PWN::Blockchain::ETH.decode_transfer(
      #   log: 'required - symbol-keyed log with topics and data; unknown signatures return nil'
      # )
      public_class_method def self.decode_transfer(opts = {})
        log = opts[:log]
        raise ArgumentError, 'log must be a hash with topics' unless log.is_a?(Hash) && log[:topics].is_a?(Array)

        topics = log[:topics]
        raise ArgumentError, 'Too many event topics' if topics.length > 4

        topics.each { |topic| hex_identifier(value: topic, size: 32) }
        return nil unless topics.first.is_a?(String) && topics.first.downcase == TRANSFER_TOPIC

        raise ArgumentError, 'Invalid Transfer topic count' unless [3, 4].include?(topics.length)

        raise ArgumentError, 'Noncanonical indexed address' unless topics[1..2].all? { |topic| topic.match?(/\A0x0{24}[0-9a-fA-F]{40}\z/) }

        result = { standard: topics.length == 3 ? :erc20 : :erc721, conformance: :unverified,
                   from: "0x#{topics[1][-40..].downcase}", to: "0x#{topics[2][-40..].downcase}" }
        if topics.length == 3
          result[:value] = hex_identifier(value: log[:data], size: 32).to_i(16)
        else
          raise ArgumentError, 'ERC721 Transfer data must be empty' unless log[:data] == '0x'

          result[:token_id] = topics[3].to_i(16)
        end
        result
      end

      private_class_method def self.numeric_range(opts = {})
        first = opts[:from_block]
        last = opts[:to_block]
        raise ArgumentError, 'Range requires nonnegative integer from_block <= to_block' unless first.is_a?(Integer) && last.is_a?(Integer) && first >= 0 && last >= first

        [first, last]
      end

      # Query bounded logs; provider truncation cannot be independently detected.
      # Supported Method Parameters::
      # PWN::Blockchain::ETH.event_logs(
      #   rpc_url: 'required - explicit Ethereum HTTP(S) JSON-RPC endpoint',
      #   from_block: 'required - nonnegative integer start height',
      #   to_block: 'required - integer inclusive end height; maximum span 1000 blocks',
      #   address: 'optional - 20-byte emitting contract address filter',
      #   topics: 'optional - up to four 32-byte topic filters or nil wildcards',
      #   limit: 'optional - returned log cap from 1 to 10000, default 1000',
      #   timeout: 'optional - request timeout in seconds from 1 to 120, default 30'
      # )
      public_class_method def self.event_logs(opts = {})
        first, last = numeric_range(opts)
        raise ArgumentError, 'Log range exceeds 1000 blocks' if last - first >= 1000

        limit = opts.fetch(:limit, 1000)
        raise ArgumentError, 'limit must be an integer from 1 to 10000' unless limit.is_a?(Integer) && limit.between?(1, 10_000)

        filter = { fromBlock: block_tag(value: first), toBlock: block_tag(value: last) }
        filter[:address] = hex_identifier(value: opts[:address], size: 20) if opts[:address]
        topics = opts.fetch(:topics, [])
        raise ArgumentError, 'topics must be an array of at most four topics' unless topics.is_a?(Array) && topics.length <= 4

        filter[:topics] = topics.map { |topic| topic.nil? ? nil : hex_identifier(value: topic, size: 32) }
        logs = rpc(opts.merge(method: 'eth_getLogs', params: [filter]))
        raise RPCError, 'Invalid logs response' unless logs.is_a?(Array)

        rows = logs.first(limit).map do |log|
          raise RPCError, 'Invalid log object' unless log.is_a?(Hash)

          hex_identifier(value: log[:address], size: 20)
          hex_data(value: log[:data])
          height = quantity(value: log[:blockNumber])
          raise RPCError, 'Provider log outside requested range' unless height.between?(first, last)

          hex_identifier(value: log[:transactionHash], size: 32)
          log.merge(transfer: decode_transfer(log: log))
        end
        { source: :ethereum_json_rpc, from_block: first, to_block: last, logs: rows,
          truncated: logs.length > limit, complete: false, provider_completeness: :unverified,
          returned_count: rows.length, internal_traces: :not_covered }
      end

      # Scan top-level transactions in bounded whole-block pages, not internal calls or token events.
      # Supported Method Parameters::
      # PWN::Blockchain::ETH.address_activity(
      #   rpc_url: 'required - explicit Ethereum HTTP(S) JSON-RPC endpoint',
      #   address: 'required - 0x-prefixed 20-byte account address',
      #   from_block: 'required - nonnegative integer page start height',
      #   to_block: 'required - integer inclusive end height',
      #   page_size: 'optional - blocks to scan from 1 to 100, default 10; resume with next_block',
      #   timeout: 'optional - request timeout in seconds from 1 to 120, default 30'
      # )
      public_class_method def self.address_activity(opts = {})
        address = hex_identifier(value: opts[:address], size: 20)
        first, last = numeric_range(opts)
        size = opts.fetch(:page_size, 10)
        raise ArgumentError, 'page_size must be an integer from 1 to 100' unless size.is_a?(Integer) && size.between?(1, 100)

        stop = [first + size - 1, last].min
        blocks = []
        transactions = []
        (first..stop).each do |height|
          data = block(opts.merge(block: height, full_transactions: true))[:block]
          raise RPCError, 'Missing or inconsistent activity block' unless data && quantity(value: data[:number]) == height && data[:transactions].is_a?(Array)

          hash = hex_identifier(value: data[:hash], size: 32)
          blocks << { number: height, hash: hash }
          data[:transactions].each do |tx|
            raise RPCError, 'Expected full transaction object' unless tx.is_a?(Hash)

            next unless [tx[:from], tx[:to]].compact.any? { |value| value.is_a?(String) && value.downcase == address }

            transactions << tx.merge(block_number: height, block_hash: hash, value_wei: quantity(value: tx[:value]))
          end
        end
        { source: :ethereum_json_rpc, address: address, transactions: transactions, blocks: blocks,
          next_block: stop < last ? stop + 1 : nil, complete: stop == last,
          coverage: :top_level_transactions_only, internal_traces: :not_covered,
          token_events: :not_covered, reorg_safe: false, from_block: first, to_block: stop }
      end

      # Execute read-only eth_call at a pinned canonical block; no signing or submission.
      # Supported Method Parameters::
      # PWN::Blockchain::ETH.call(
      #   rpc_url: 'required - explicit Ethereum HTTP(S) JSON-RPC endpoint',
      #   contract: 'required - 0x-prefixed 20-byte contract address',
      #   data: 'required - ABI-encoded even-length 0x-prefixed calldata, maximum 128 KiB',
      #   block: 'optional - block number, hash or stable tag, default latest',
      #   timeout: 'optional - request timeout in seconds from 1 to 120, default 30'
      # )
      public_class_method def self.call(opts = {})
        address = hex_identifier(value: opts[:contract], size: 20)
        data = hex_data(value: opts[:data])
        raise ArgumentError, 'Calldata exceeds 128 KiB' if data.length > 262_146

        context = snapshot(opts)
        params = [{ to: address, data: data }, { blockHash: context[:block_hash], requireCanonical: true }]
        result = hex_data(value: rpc(opts.merge(method: 'eth_call', params: params)))
        context.merge(source: :ethereum_json_rpc, contract: address, data: result)
      end

      # Read optional token metadata; layouts do not prove ERC conformance, and RPC failures propagate.
      # Supported Method Parameters::
      # PWN::Blockchain::ETH.token_metadata(
      #   rpc_url: 'required - explicit Ethereum HTTP(S) JSON-RPC endpoint supporting EIP-1898',
      #   contract: 'required - 0x-prefixed 20-byte token contract address',
      #   block: 'optional - integer, hash or stable tag for pinned reads, default latest',
      #   timeout: 'optional - request timeout from 1 to 120 seconds, default 30'
      # )
      public_class_method def self.token_metadata(opts = {})
        contract = hex_identifier(value: opts[:contract], size: 20)
        context = snapshot(opts)
        result = context.merge(source: :ethereum_json_rpc, contract: contract, conformance: :unverified, unavailable: [])
        { name: '0x06fdde03', symbol: '0x95d89b41', decimals: '0x313ce567', total_supply: '0x18160ddd' }.each do |field, selector|
          params = [{ to: contract, data: selector }, { blockHash: context[:block_hash], requireCanonical: true }]
          raw = hex_data(value: rpc(opts.merge(method: 'eth_call', params: params)))
          value = if %i[name symbol].include?(field)
                    abi_string(value: raw)
                  elsif raw.match?(/\A0x[0-9a-fA-F]{64}\z/)
                    raw.to_i(16)
                  end
          value = nil if field == :decimals && value && value > 255
          result[field] = value
          result[:unavailable] << field if value.nil?
        end
        result
      end

      private_class_method def self.abi_string(opts = {})
        hex = opts[:value][2..]
        return nil if hex.empty? || hex.length > 16_384

        if hex.length == 64
          bytes = [hex].pack('H*').sub(/\x00+\z/, '')
        else
          return nil unless hex.length >= 128 && hex[0, 64].to_i(16) == 32

          length = hex[64, 64].to_i(16)
          padded = ((length + 31) / 32) * 64
          return nil unless length <= 4096 && hex.length == 128 + padded
          return nil unless hex[(128 + (length * 2))..].match?(/\A0*\z/)

          bytes = [hex[128, length * 2]].pack('H*')
        end
        bytes.force_encoding(Encoding::UTF_8)
        bytes.valid_encoding? ? bytes : nil
      end

      private_class_method def self.hex_identifier(opts = {})
        value = opts[:value]
        size = opts[:size]
        raise ArgumentError, "Expected 0x-prefixed #{size}-byte identifier" unless value.is_a?(String) && value.match?(/\A0x[0-9a-fA-F]{#{size * 2}}\z/)

        value.downcase
      end

      private_class_method def self.block_tag(opts = {})
        value = opts[:value]
        return "0x#{value.to_s(16)}" if value.is_a?(Integer) && value >= 0
        return value if value.is_a?(String) && (value.match?(/\A0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)\z/) || %w[latest earliest pending safe finalized].include?(value))

        raise ArgumentError, 'Invalid block number or tag'
      end

      private_class_method def self.hex_data(opts = {})
        value = opts[:value]
        raise RPCError, 'Invalid hex data' unless value.is_a?(String) && value.match?(/\A0x(?:[0-9a-fA-F]{2})*\z/)

        value
      end

      # Read a block by number, tag or hash; raw quantities remain exact hex.
      # Supported Method Parameters::
      # PWN::Blockchain::ETH.block(
      #   rpc_url: 'required - explicit Ethereum HTTP(S) JSON-RPC endpoint',
      #   block: 'optional - nonnegative integer, canonical hex quantity, tag or 32-byte hash; default latest',
      #   full_transactions: 'optional - boolean to return transaction objects, default false',
      #   timeout: 'optional - request timeout in seconds from 1 to 120, default 30'
      # )
      public_class_method def self.block(opts = {})
        selector = opts.key?(:block) ? opts[:block] : 'latest'
        full = opts.fetch(:full_transactions, false)
        raise ArgumentError, 'full_transactions must be boolean' unless [true, false].include?(full)

        by_hash = selector.is_a?(String) && selector.match?(/\A0x[0-9a-fA-F]{64}\z/)
        selector = by_hash ? hex_identifier(value: selector, size: 32) : block_tag(value: selector)
        result = rpc(opts.merge(method: by_hash ? 'eth_getBlockByHash' : 'eth_getBlockByNumber', params: [selector, full]))
        raise RPCError, 'Invalid block response' unless result.nil? || result.is_a?(Hash)

        if result && selector != 'pending'
          hash = hex_identifier(value: result[:hash], size: 32)
          number = quantity(value: result[:number])
          raise RPCError, 'Block hash does not match request' if by_hash && hash != selector
          raise RPCError, 'Block height does not match request' if !by_hash && selector.start_with?('0x') && number != quantity(value: selector)
        end
        { source: :ethereum_json_rpc, requested_block: selector, block: result }
      end

      private_class_method def self.snapshot(opts = {})
        raise ArgumentError, 'Pending block cannot pin state' if opts[:block] == 'pending'

        result = block(opts)[:block]
        raise RPCError, 'Block not found or pending; stable block required' unless result && result[:number] && result[:hash]

        { block_number: quantity(value: result[:number]), block_hash: hex_identifier(value: result[:hash], size: 32) }
      end

      # Inspect balance, nonce and bytecode at one pinned block hash.
      # Supported Method Parameters::
      # PWN::Blockchain::ETH.account(
      #   rpc_url: 'required - explicit Ethereum HTTP(S) JSON-RPC endpoint',
      #   address: 'required - 0x-prefixed 20-byte account address',
      #   block: 'optional - block number, hash or stable tag, default latest',
      #   timeout: 'optional - request timeout in seconds from 1 to 120, default 30'
      # )
      public_class_method def self.account(opts = {})
        address = hex_identifier(value: opts[:address], size: 20)
        context = snapshot(opts)
        params = [address, { blockHash: context[:block_hash], requireCanonical: true }]
        context.merge(source: :ethereum_json_rpc, address: address,
                      balance_wei: quantity(value: rpc(opts.merge(method: 'eth_getBalance', params: params))),
                      nonce: quantity(value: rpc(opts.merge(method: 'eth_getTransactionCount', params: params))),
                      code: hex_data(value: rpc(opts.merge(method: 'eth_getCode', params: params))))
      end

      # Inspect transaction and receipt; fees exclude chain-specific L2 surcharges.
      # Supported Method Parameters::
      # PWN::Blockchain::ETH.transaction(
      #   rpc_url: 'required - explicit Ethereum HTTP(S) JSON-RPC endpoint',
      #   hash: 'required - 0x-prefixed 32-byte transaction hash',
      #   timeout: 'optional - request timeout in seconds from 1 to 120, default 30'
      # )
      public_class_method def self.transaction(opts = {})
        hash = hex_identifier(value: opts[:hash], size: 32)
        tx = rpc(opts.merge(method: 'eth_getTransactionByHash', params: [hash]))
        result = { source: :ethereum_json_rpc, hash: hash, internal_traces: :not_covered }
        return result.merge(status: :not_found) if tx.nil?

        raise RPCError, 'Invalid transaction response' unless tx.is_a?(Hash) && tx[:hash]&.downcase == hash

        receipt = rpc(opts.merge(method: 'eth_getTransactionReceipt', params: [hash]))
        result.merge!(transaction: tx, receipt: receipt, value_wei: quantity(value: tx[:value]), block_number: tx[:blockNumber] && quantity(value: tx[:blockNumber]))
        return result.merge(status: tx[:blockNumber] ? :receipt_unavailable : :pending) unless receipt

        raise RPCError, 'Invalid receipt response' unless receipt.is_a?(Hash) && receipt[:transactionHash]&.downcase == hash

        raise RPCError, 'Transaction and receipt inclusion heights differ' if receipt[:blockNumber] && receipt[:blockNumber] != tx[:blockNumber]
        raise RPCError, 'Transaction and receipt block hashes differ' if receipt[:blockHash] && tx[:blockHash] && receipt[:blockHash].downcase != tx[:blockHash].downcase

        status = receipt[:status] && quantity(value: receipt[:status])
        raise RPCError, 'Invalid receipt status' unless [nil, 0, 1].include?(status)

        gas_price = receipt[:effectiveGasPrice] || tx[:gasPrice]
        fee = gas_price && (quantity(value: receipt[:gasUsed]) * quantity(value: gas_price))
        blob_fee = (quantity(value: receipt[:blobGasUsed]) * quantity(value: receipt[:blobGasPrice]) if receipt[:blobGasUsed] && receipt[:blobGasPrice])
        result.merge(status: { 0 => :reverted, 1 => :success }.fetch(status, :unknown),
                     block_hash: receipt[:blockHash], execution_fee_wei: fee, blob_fee_wei: blob_fee,
                     fee_scope: :execution_and_blob_only, contract_creation: tx[:to].nil?, contract_address: receipt[:contractAddress])
      end

      private_class_method def self.quantity(opts = {})
        value = opts[:value]
        raise RPCError, 'Invalid RPC quantity' unless value.is_a?(String) && value.match?(/\A0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)\z/)

        value.to_i(16)
      end

      private_class_method def self.rpc(opts = {})
        uri = URI.parse(opts[:rpc_url].to_s)
        raise ArgumentError, 'rpc_url must be an explicit HTTP(S) endpoint without userinfo or fragment' unless %w[http https].include?(uri.scheme) && uri.host && !uri.userinfo && !uri.fragment

        timeout = opts.fetch(:timeout, 30)
        raise ArgumentError, 'timeout must be an integer from 1 to 120' unless timeout.is_a?(Integer) && timeout.between?(1, 120)

        response = RestClient::Request.execute(
          method: :post, url: uri.to_s,
          headers: { content_type: :json, accept: :json },
          payload: JSON.generate(jsonrpc: '2.0', id: 1, method: opts[:method], params: opts.fetch(:params, [])),
          verify_ssl: OpenSSL::SSL::VERIFY_PEER, open_timeout: 10, timeout: timeout,
          max_redirects: 0
        )
        body = JSON.parse(response.body, symbolize_names: true)
        raise RPCError, 'Invalid JSON-RPC envelope' unless body.is_a?(Hash) && body[:jsonrpc] == '2.0' && body[:id] == 1
        raise RPCError, 'JSON-RPC provider returned an error' if body.key?(:error)
        raise RPCError, 'Missing JSON-RPC result' unless body.key?(:result)

        body[:result]
      rescue URI::InvalidURIError
        raise ArgumentError, 'Invalid rpc_url', cause: nil
      rescue RestClient::Exception, OpenSSL::SSL::SSLError, IOError, SystemCallError, SocketError, Timeout::Error
        raise RPCError, 'Ethereum HTTP transport failed', cause: nil
      rescue JSON::ParserError
        raise RPCError, 'Invalid JSON-RPC JSON response', cause: nil
      end

      # Read the endpoint chain identity, head height and sync state.
      # Supported Method Parameters::
      # PWN::Blockchain::ETH.chain_status(
      #   rpc_url: 'required - explicit Ethereum HTTP(S) JSON-RPC endpoint',
      #   timeout: 'optional - request timeout in seconds from 1 to 120, default 30'
      # )
      public_class_method def self.chain_status(opts = {})
        rpc_url = opts[:rpc_url]
        context = opts.merge(rpc_url: rpc_url)
        {
          source: :ethereum_json_rpc,
          chain_id: quantity(value: rpc(context.merge(method: 'eth_chainId'))),
          block_number: quantity(value: rpc(context.merge(method: 'eth_blockNumber'))),
          syncing: rpc(context.merge(method: 'eth_syncing'))
        }
      end

      # Internal read-only BlockCypher transport.
      private_class_method def self.eth_rest_call(opts = {})
        RestClient::Request.execute(
          method: :get, url: "https://api.blockcypher.com/v1/eth/#{opts[:rest_call]}",
          headers: { content_type: :json, params: opts[:params] },
          verify_ssl: OpenSSL::SSL::VERIFY_PEER, timeout: 30, open_timeout: 10, max_redirects: 0
        )
      rescue RestClient::Exception, OpenSSL::SSL::SSLError, IOError, SystemCallError, SocketError, Timeout::Error
        raise RPCError, 'BlockCypher HTTP transport failed', cause: nil
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
      rescue JSON::ParserError
        raise RPCError, 'Invalid BlockCypher JSON response', cause: nil
      end

      # Supported Method Parameters::
      # PWN::Blockchain::ETH.get_block_details(
      #   height: 'required - block height number',
      #   token: 'optional - API token for higher rate limits'
      # )
      public_class_method def self.get_block_details(opts = {})
        height = opts[:height]
        raise ArgumentError, 'height must be a nonnegative integer or decimal string' unless (height.is_a?(Integer) && height >= 0) || (height.is_a?(String) && height.match?(/\A(?:0|[1-9][0-9]*)\z/))

        params = {}
        params[:token] = opts[:token] if opts[:token]

        rest_call = "main/blocks/#{height}"
        response = eth_rest_call(rest_call: rest_call, params: params)

        JSON.parse(response.body, symbolize_names: true)
      rescue JSON::ParserError
        raise RPCError, 'Invalid BlockCypher JSON response', cause: nil
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
          # Read endpoint chain identity, height and synchronization state.
          #{self}.chain_status(
            rpc_url: 'required - explicit HTTP(S) JSON-RPC endpoint; never persisted',
            timeout: 'optional - request timeout from 1 to 120 seconds, default 30'
          )

          # Read a block with raw exact hex quantities.
          #{self}.block(
            rpc_url: 'required - explicit HTTP(S) JSON-RPC endpoint',
            block: 'optional - integer, canonical hex quantity, tag or 32-byte hash; default latest',
            full_transactions: 'optional - boolean transaction object expansion, default false',
            timeout: 'optional - request timeout from 1 to 120 seconds, default 30'
          )

          # Inspect receipt status and exact execution/blob fees, excluding L2 surcharges.
          #{self}.transaction(
            rpc_url: 'required - explicit HTTP(S) JSON-RPC endpoint',
            hash: 'required - 0x-prefixed 32-byte transaction hash',
            timeout: 'optional - request timeout from 1 to 120 seconds, default 30'
          )

          # Inspect balance, nonce and code using EIP-1898 pinned canonical block reads.
          #{self}.account(
            rpc_url: 'required - explicit HTTP(S) JSON-RPC endpoint supporting EIP-1898',
            address: 'required - 0x-prefixed 20-byte account address',
            block: 'optional - integer, canonical hex, hash or stable tag; default latest',
            timeout: 'optional - request timeout from 1 to 120 seconds, default 30'
          )

          # Query bounded event logs; silent provider truncation remains unverified.
          #{self}.event_logs(
            rpc_url: 'required - explicit HTTP(S) JSON-RPC endpoint',
            from_block: 'required - nonnegative integer start height',
            to_block: 'required - inclusive integer end height; maximum 1000 blocks',
            address: 'optional - 0x-prefixed 20-byte emitting contract address',
            topics: 'optional - array of at most four 32-byte topics or nil wildcards',
            limit: 'optional - result cap from 1 to 10000, default 1000; truncation is explicit',
            timeout: 'optional - request timeout from 1 to 120 seconds, default 30'
          )

          # Decode standard ERC20/ERC721 Transfer layouts, not ERC1155 or proven conformance.
          #{self}.decode_transfer(
            log: 'required - symbol-keyed log with topics and data; unknown signatures return nil'
          )

          # Scan whole-block pages of top-level transactions; no token events or internal traces.
          #{self}.address_activity(
            rpc_url: 'required - explicit HTTP(S) JSON-RPC endpoint',
            address: 'required - 0x-prefixed 20-byte account address',
            from_block: 'required - nonnegative integer page start; resume with next_block',
            to_block: 'required - inclusive integer end height',
            page_size: 'optional - blocks per page from 1 to 100, default 10',
            timeout: 'optional - request timeout from 1 to 120 seconds, default 30'
          )

          # Execute ABI-encoded read-only eth_call at a pinned block, never send or sign.
          #{self}.call(
            rpc_url: 'required - explicit HTTP(S) JSON-RPC endpoint supporting EIP-1898',
            contract: 'required - 0x-prefixed 20-byte contract address',
            data: 'required - even-length 0x-prefixed ABI calldata, maximum 128 KiB',
            block: 'optional - integer, canonical hex, hash or stable tag; default latest',
            timeout: 'optional - request timeout from 1 to 120 seconds, default 30'
          )

          # Read token metadata at one block; empty/malformed ABI fields are unavailable, RPC errors propagate.
          #{self}.token_metadata(
            rpc_url: 'required - explicit HTTP(S) JSON-RPC endpoint supporting EIP-1898',
            contract: 'required - 0x-prefixed 20-byte token contract address',
            block: 'optional - integer, canonical hex, hash or stable tag; default latest',
            timeout: 'optional - request timeout from 1 to 120 seconds, default 30'
          )

          # Coverage excludes internal traces. Activity completeness is only for the requested
          # top-level range; block pages can reorganize. Use finalized ranges where possible.
          # RPC errors are redacted. No implicit endpoint, keys, signing or wallet changes.

          # Run get latest block and return its result
          #{self}.get_latest_block(
            token: 'optional - API token for higher rate limits'
          )

          # Run get block details and return its result
          #{self}.get_block_details(
            height: 'required - block height number',
            token: 'optional - API token for higher rate limits'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
