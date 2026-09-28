# frozen_string_literal: true

require 'json'
require 'net/http'
require 'openssl'
require 'bigdecimal'
require 'date'
require 'timeout'

module PWN
  module Blockchain
    # Read-only Bitcoin Core intelligence. No wallet, signing or broadcast RPCs.
    module BTC
      # Deliberately excludes remote messages/bodies, URLs and credentials.
      class RPCError < StandardError
        attr_reader :code, :http_status, :rpc_method

        def initialize(opts = {})
          @code = opts[:code]
          @http_status = opts[:http_status]
          @rpc_method = opts[:rpc_method]
          super("Bitcoin RPC #{opts[:kind] || 'failed'} (method=#{@rpc_method}, code=#{@code}, HTTP=#{@http_status})")
        end
      end

      READ_METHODS = %w[getblockchaininfo getblockhash getblock getblockheader getrawtransaction gettxout getmempoolinfo validateaddress].freeze

      private_class_method def self.integer_option(opts = {})
        value = opts[:value]
        range = opts[:range]
        raise ArgumentError, "#{opts[:name]} must be an integer in #{range}" unless value.is_a?(Integer) && range.cover?(value)

        value
      end

      private_class_method def self.hash_option(opts = {})
        value = opts[:value]
        raise ArgumentError, "#{opts[:name]} must be a 64-character hexadecimal string" unless value.is_a?(String) && value.match?(/\A[0-9a-fA-F]{64}\z/)

        value
      end

      private_class_method def self.btc_rpc_call(opts = {})
        method = opts[:method]
        raise ArgumentError, 'Unsupported read-only RPC method' unless READ_METHODS.include?(method)

        config = PWN::Env.dig(:plugins, :blockchain, :bitcoin)
        raise ArgumentError, 'Bitcoin RPC configuration is required' unless config.is_a?(Hash)

        host = config.fetch(:rpc_host, '127.0.0.1')
        scheme = config.fetch(:rpc_scheme, 'http')
        raise ArgumentError, 'Invalid Bitcoin RPC host or scheme' unless host.is_a?(String) && host.match?(/\A[a-zA-Z0-9.:-]+\z/) && %w[http https].include?(scheme)

        port = config.fetch(:rpc_port, 8332)
        port = port.to_i if port.is_a?(String) && port.match?(/\A[0-9]+\z/)
        integer_option(value: port, name: 'rpc_port', range: 1..65_535)
        user = config[:rpc_user]
        password = config[:rpc_pass]
        raise ArgumentError, 'Bitcoin RPC credentials are required and must be valid strings' unless user.is_a?(String) && !user.empty? && !user.match?(/[:\r\n]/) && password.is_a?(String) && !password.empty? && !password.match?(/[\r\n]/)

        timeout = integer_option(value: opts.fetch(:timeout, 30), name: 'timeout', range: 1..300)
        begin
          http = Net::HTTP.new(host, port, nil) # Never inherit proxy environment or forward credentials.
          http.use_ssl = scheme == 'https'
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          http.open_timeout = [timeout, 10].min
          http.read_timeout = timeout
          http.write_timeout = timeout
          request = Net::HTTP::Post.new('/')
          request.basic_auth(user, password)
          request['Content-Type'] = 'application/json'
          request.body = JSON.generate(jsonrpc: '1.0', id: 'pwn-btc', method: method, params: opts.fetch(:params, []))
          response = Timeout.timeout(timeout) { http.request(request) }
          status = response.code.to_i
          body = JSON.parse(response.body, symbolize_names: true, decimal_class: BigDecimal)
          raise RPCError.new(rpc_method: method, http_status: status, kind: 'invalid response'), cause: nil unless body.is_a?(Hash) && body[:id] == 'pwn-btc' && (body.key?(:result) || body[:error].is_a?(Hash))

          if body[:error]
            code = body[:error].is_a?(Hash) && body[:error][:code].is_a?(Integer) ? body[:error][:code] : nil
            raise RPCError.new(rpc_method: method, http_status: status, code: code), cause: nil
          end
          raise RPCError.new(rpc_method: method, http_status: status, kind: 'HTTP failure'), cause: nil unless status == 200

          body
        rescue RPCError
          raise
        rescue StandardError
          raise RPCError.new(rpc_method: method, http_status: status, kind: 'transport or response failure'), cause: nil
        end
      end

      # Supported Method Parameters::
      # Return the legacy JSON-RPC envelope with blockchain status, without AI.
      # PWN::Blockchain::BTC.get_latest_block
      public_class_method def self.get_latest_block
        btc_rpc_call(method: 'getblockchaininfo')
      end

      # Supported Method Parameters::
      # Return blockchain synchronization, pruning and active chain status.
      # PWN::Blockchain::BTC.chain_status(timeout: 'optional - RPC timeout seconds, 1..300; default 30')
      public_class_method def self.chain_status(opts = {})
        timeout = opts.key?(:timeout) ? opts[:timeout] : 30
        btc_rpc_call(method: 'getblockchaininfo', timeout: timeout)[:result]
      end

      # Supported Method Parameters::
      # Read a block at a height with selectable Core verbosity.
      # PWN::Blockchain::BTC.get_block_details(
      #   height: 'optional - nonnegative integer height; default current tip',
      #   verbosity: 'optional - integer 0..3; default 1; 3 requires node undo data',
      #   timeout: 'optional - RPC timeout seconds, 1..300; default 30'
      # )
      public_class_method def self.get_block_details(opts = {})
        timeout = opts.fetch(:timeout, 30)
        verbosity = integer_option(value: opts.fetch(:verbosity, 1), name: 'verbosity', range: 0..3)
        height = opts[:height]
        height = chain_status(timeout: timeout)[:blocks] if height.nil?
        integer_option(value: height, name: 'height', range: 0..2_147_483_647)
        hash = btc_rpc_call(method: 'getblockhash', params: [height], timeout: timeout)[:result]
        btc_rpc_call(method: 'getblock', params: [hash, verbosity], timeout: timeout)[:result]
      end

      private_class_method def self.satoshis(opts = {})
        amount = BigDecimal(opts[:value].to_s, exception: false)
        raise RPCError.new(kind: 'invalid monetary amount'), cause: nil unless amount&.finite? && amount >= 0 && amount <= 21_000_000 && (amount * 100_000_000).frac.zero?

        (amount * 100_000_000).to_i
      end

      private_class_method def self.raw_transaction(opts = {})
        params = [opts[:txid], true]
        params << opts[:blockhash] if opts[:blockhash]
        result = btc_rpc_call(method: 'getrawtransaction', params: params, timeout: opts[:timeout])[:result]
        raise RPCError.new(rpc_method: 'getrawtransaction', kind: 'invalid transaction'), cause: nil unless result.is_a?(Hash) && result[:txid]&.downcase == opts[:txid].downcase && result[:vin].is_a?(Array) && result[:vout].is_a?(Array)

        result
      end

      private_class_method def self.resolve_prevout(opts = {})
        input = opts[:input]
        return [input[:prevout], nil] if input[:prevout].is_a?(Hash)

        cache = opts[:cache]
        budget = opts[:budget]
        unless cache.key?(input[:txid])
          return [nil, :lookup_limit] if budget[:remaining].zero?

          budget[:remaining] -= 1
          begin
            cache[input[:txid]] = raw_transaction(txid: input[:txid], timeout: opts[:timeout])
          rescue RPCError => e
            raise unless [-5, -8, -1].include?(e.code) && [200, 500].include?(e.http_status)

            cache[input[:txid]] = nil
          end
        end
        prevout = cache[input[:txid]]&.fetch(:vout)&.find { |output| output[:n] == input[:vout] }
        [prevout, prevout ? nil : :unavailable]
      end

      private_class_method def self.transaction_details(opts = {})
        tx = opts[:transaction]
        missing = []
        inputs = tx[:vin].map do |input|
          next { coinbase: input[:coinbase], value_sats: nil } if input.key?(:coinbase)

          prevout, reason = resolve_prevout(input: input, cache: opts[:cache], budget: opts[:budget], timeout: opts[:timeout])
          reference = { txid: input[:txid], vout: input[:vout] }
          missing << reference.merge(reason: reason) unless prevout
          reference.merge(value_sats: prevout ? satoshis(value: prevout[:value]) : nil, script_pub_key: prevout&.dig(:scriptPubKey))
        end
        outputs = tx[:vout].map { |output| { n: output[:n], value_sats: satoshis(value: output[:value]), script_pub_key: output[:scriptPubKey] } }
        coinbase = tx[:vin].any? { |input| input.key?(:coinbase) }
        output_total = outputs.sum { |output| output[:value_sats] }
        input_total = !coinbase && missing.empty? ? inputs.sum { |input| input[:value_sats] } : nil
        {
          txid: tx[:txid], blockhash: tx[:blockhash], confirmations: tx[:confirmations],
          coinbase: coinbase, inputs: inputs, outputs: outputs,
          input_sats: input_total, output_sats: output_total,
          fee_sats: input_total ? input_total - output_total : nil,
          prevouts_complete: missing.empty?, missing_prevouts: missing
        }
      end

      # Supported Method Parameters::
      # Inspect transaction amounts and proven input fees; unavailable prevouts remain explicit.
      # PWN::Blockchain::BTC.inspect_transaction(
      #   txid: 'required - 64-character transaction hash',
      #   blockhash: 'optional - containing block hash for nodes without txindex',
      #   max_prevouts: 'optional - maximum parent RPC lookups, 0..1000; default 100',
      #   timeout: 'optional - RPC timeout seconds, 1..300; default 30'
      # )
      public_class_method def self.inspect_transaction(opts = {})
        txid = hash_option(value: opts[:txid], name: 'txid')
        blockhash = opts[:blockhash]
        hash_option(value: blockhash, name: 'blockhash') unless blockhash.nil?
        budget = { remaining: integer_option(value: opts.fetch(:max_prevouts, 100), name: 'max_prevouts', range: 0..1000) }
        timeout = opts.fetch(:timeout, 30)
        tx = raw_transaction(txid: txid, blockhash: blockhash, timeout: timeout)
        transaction_details(transaction: tx, budget: budget, cache: {}, timeout: timeout)
      end

      # Supported Method Parameters::
      # Inspect an outpoint in the current UTXO view; null means spent or unknown, not proven spent.
      # PWN::Blockchain::BTC.inspect_outpoint(
      #   txid: 'required - 64-character transaction hash',
      #   vout: 'required - nonnegative integer output index',
      #   include_mempool: 'optional - boolean include mempool effects; default true',
      #   timeout: 'optional - RPC timeout seconds, 1..300; default 30'
      # )
      public_class_method def self.inspect_outpoint(opts = {})
        txid = hash_option(value: opts[:txid], name: 'txid')
        vout = integer_option(value: opts[:vout], name: 'vout', range: 0..4_294_967_295)
        include_mempool = opts.fetch(:include_mempool, true)
        raise ArgumentError, 'include_mempool must be boolean' unless [true, false].include?(include_mempool)

        result = btc_rpc_call(method: 'gettxout', params: [txid, vout, include_mempool], timeout: opts.fetch(:timeout, 30))[:result]
        base = { txid: txid, vout: vout, include_mempool: include_mempool, unspent: !result.nil? }
        return base.merge(status: :spent_or_unknown) if result.nil?

        base.merge(status: :unspent, value_sats: satoshis(value: result[:value]), evidence: result)
      end

      # Supported Method Parameters::
      # Read aggregate mempool statistics without enumerating transactions.
      # PWN::Blockchain::BTC.mempool_summary(timeout: 'optional - RPC timeout seconds, 1..300; default 30')
      public_class_method def self.mempool_summary(opts = {})
        timeout = opts.key?(:timeout) ? opts[:timeout] : 30
        btc_rpc_call(method: 'getmempoolinfo', timeout: timeout)[:result]
      end

      # Supported Method Parameters::
      # Trace only transaction ancestors using input references, never ownership or change heuristics.
      # PWN::Blockchain::BTC.trace_transaction(
      #   txid: 'required - root transaction hash, 64 hexadecimal characters',
      #   blockhash: 'optional - containing block hash for root lookup without txindex',
      #   max_depth: 'optional - ancestor depth 0..100; default 3',
      #   max_transactions: 'optional - total transaction RPC budget 1..1000; default 100',
      #   max_edges: 'optional - maximum evidence edges 1..10000; default 1000',
      #   timeout: 'optional - per-RPC timeout seconds, 1..300; default 30'
      # )
      public_class_method def self.trace_transaction(opts = {})
        txid = hash_option(value: opts[:txid], name: 'txid')
        blockhash = opts[:blockhash]
        hash_option(value: blockhash, name: 'blockhash') unless blockhash.nil?
        limits = {
          depth: integer_option(value: opts.fetch(:max_depth, 3), name: 'max_depth', range: 0..100),
          transactions: integer_option(value: opts.fetch(:max_transactions, 100), name: 'max_transactions', range: 1..1000),
          edges: integer_option(value: opts.fetch(:max_edges, 1000), name: 'max_edges', range: 1..10_000)
        }
        timeout = opts.fetch(:timeout, 30)
        state = { queue: [[txid, 0]], scheduled: { txid.downcase => true }, cache: {}, edges: [], reasons: [], missing: [] }
        until state[:queue].empty?
          current, depth = state[:queue].shift
          begin
            tx = raw_transaction(txid: current, blockhash: current == txid ? blockhash : nil, timeout: timeout)
          rescue RPCError => e
            raise unless current != txid && [-5, -8, -1].include?(e.code) && [200, 500].include?(e.http_status)

            state[:cache][current.downcase] = nil
            state[:missing] << { txid: current, code: e.code }
            next
          end
          state[:cache][current.downcase] = tx
          trace_inputs(transaction: tx, depth: depth, state: state, limits: limits)
        end
        finish_trace(state: state, txid: txid)
      end

      private_class_method def self.trace_inputs(opts = {})
        tx = opts[:transaction]
        state = opts[:state]
        limits = opts[:limits]
        depth = opts[:depth]
        tx[:vin].each_with_index do |input, index|
          next if input.key?(:coinbase)

          if state[:edges].length >= limits[:edges]
            state[:reasons] << :max_edges
            break
          end
          state[:edges] << { from_txid: input[:txid], from_vout: input[:vout], to_txid: tx[:txid], to_vin: index, value_sats: nil, evidence: :vin_reference }
          next if state[:scheduled].key?(input[:txid])

          if depth >= limits[:depth]
            state[:reasons] << :max_depth
          elsif state[:scheduled].length >= limits[:transactions]
            state[:reasons] << :max_transactions
          else
            state[:scheduled][input[:txid]] = true
            state[:queue] << [input[:txid], depth + 1]
          end
        end
      end

      private_class_method def self.finish_trace(opts = {})
        state = opts[:state]
        missing = []
        state[:edges].each do |edge|
          input = state[:cache][edge[:to_txid]][:vin][edge[:to_vin]]
          prevout, reason = resolve_prevout(input: input, cache: state[:cache], budget: { remaining: 0 })
          if prevout
            edge[:value_sats] = satoshis(value: prevout[:value])
          else
            missing << { txid: input[:txid], vout: input[:vout], spending_txid: edge[:to_txid], reason: reason }
          end
        end
        reasons = state[:reasons].uniq
        {
          txid: opts[:txid], direction: :ancestors, evidence: :transaction_input_references,
          nodes: state[:cache].values.compact.map { |tx| tx.slice(:txid, :blockhash, :confirmations) },
          edges: state[:edges], missing_transactions: state[:missing], missing_prevouts: missing,
          truncated: !reasons.empty?, truncation_reasons: reasons,
          complete: reasons.empty? && state[:missing].empty? && missing.empty?,
          limitations: 'Ancestors only; edges prove spends, not ownership or allocation of value to later outputs. No atomic chain snapshot.'
        }
      end

      private_class_method def self.scan_bounds(opts = {})
        first = integer_option(value: opts[:start_height], name: 'start_height', range: 0..2_147_483_647)
        last = integer_option(value: opts[:end_height], name: 'end_height', range: first..2_147_483_647)
        limit = integer_option(value: opts.fetch(:max_blocks, 100), name: 'max_blocks', range: 1..1000)
        { first: first, last: last, page_end: [last, first + limit - 1].min }
      end

      # Only parameter rejection permits an older-node fallback. Missing undo/block
      # data and transport/authentication failures must retain their evidence gaps.
      private_class_method def self.scan_block(opts = {})
        get_block_details(opts)
      rescue RPCError => e
        raise unless opts[:verbosity] == 3 && e.rpc_method == 'getblock' && [-8, -32_602].include?(e.code) && [200, 500].include?(e.http_status)

        get_block_details(opts.merge(verbosity: 2))
      end

      private_class_method def self.scan_page(opts = {})
        bounds = opts[:bounds]
        timeout = opts[:timeout]
        info = chain_status(timeout: timeout)
        raise ArgumentError, 'end_height exceeds current chain tip' if bounds[:last] > info[:blocks]

        anchor = btc_rpc_call(method: 'getblockhash', params: [bounds[:last]], timeout: timeout)[:result]
        blocks = []
        missing = []
        reorg = false
        (bounds[:first]..bounds[:page_end]).each do |height|
          begin
            block = scan_block(height: height, verbosity: opts[:verbosity], timeout: timeout)
          rescue RPCError => e
            raise unless [-1, -5, -8].include?(e.code) && [200, 500].include?(e.http_status)

            missing << { height: height, code: e.code }
            next
          end
          prior = blocks.last
          reorg = true if prior && prior[:height] == height - 1 && block[:previousblockhash] != prior[:hash]
          blocks << block.slice(:height, :hash, :time)
          opts[:on_block]&.call(block)
        end
        after = btc_rpc_call(method: 'getblockhash', params: [bounds[:last]], timeout: timeout)[:result]
        reorg ||= anchor != after
        unless blocks.empty?
          active = btc_rpc_call(method: 'getblockhash', params: [blocks.last[:height]], timeout: timeout)[:result]
          reorg ||= active != blocks.last[:hash]
        end
        truncated = bounds[:page_end] < bounds[:last]
        {
          scope: :explicit_height_range, start_height: bounds[:first], end_height: bounds[:last],
          scanned_through: bounds[:page_end], next_height: truncated ? bounds[:page_end] + 1 : nil,
          truncated: truncated, complete: !truncated && missing.empty? && !reorg,
          reorg_detected: reorg, missing_blocks: missing,
          blocks: blocks.map { |block| block.slice(:height, :hash, :time) },
          anchor: { chain: info[:chain], height: bounds[:last], hash: anchor, hash_after: after },
          limitations: 'Completeness applies only to requested heights, not all history. Non-atomic RPC scan; recheck anchors across pages and retry on reorg.'
        }
      end

      private_class_method def self.date_timestamp(opts = {})
        value = opts[:value]
        raise ArgumentError, 'Dates must be valid YYYY-MM-DD strings' unless value.is_a?(String) && value.match?(/\A\d{4}-\d{2}-\d{2}\z/)

        date = Date.iso8601(value)
        Time.utc(date.year, date.month, date.day).to_i
      rescue Date::Error
        raise ArgumentError, 'Dates must be valid YYYY-MM-DD strings', cause: nil
      end

      # Supported Method Parameters::
      # Scan a bounded page by UTC block-header dates without assuming monotonic timestamps.
      # PWN::Blockchain::BTC.scan_transactions(
      #   from: 'required - inclusive UTC date YYYY-MM-DD',
      #   to: 'required - inclusive UTC date YYYY-MM-DD',
      #   start_height: 'required - first nonnegative integer height; use next_height for continuation',
      #   end_height: 'required - final inclusive integer height; keep fixed across pages',
      #   max_blocks: 'optional - blocks examined per page, 1..1000; default 100',
      #   timeout: 'optional - per-RPC timeout seconds, 1..300; default 30'
      # )
      public_class_method def self.scan_transactions(opts = {})
        from = date_timestamp(value: opts[:from])
        to = date_timestamp(value: opts[:to])
        raise ArgumentError, 'from must not follow to' if from > to

        bounds = scan_bounds(opts)
        transactions = []
        on_block = lambda do |block|
          next unless block[:time] >= from && block[:time] < to + 86_400

          block[:tx].each { |txid| transactions << { txid: txid, height: block[:height], blockhash: block[:hash], time: block[:time] } }
        end
        scan_page(bounds: bounds, verbosity: 1, timeout: opts.fetch(:timeout, 30), on_block: on_block).merge(transactions: transactions)
      end

      # Supported Method Parameters::
      # Return legacy transaction IDs only when the entire explicit height range was scanned.
      # PWN::Blockchain::BTC.get_transactions(
      #   from: 'required - inclusive UTC date YYYY-MM-DD',
      #   to: 'required - inclusive UTC date YYYY-MM-DD',
      #   start_height: 'required - first nonnegative integer height',
      #   end_height: 'required - final inclusive integer height',
      #   max_blocks: 'optional - full-range budget 1..1000; default 100; use scan_transactions for pages',
      #   timeout: 'optional - per-RPC timeout seconds, 1..300; default 30'
      # )
      public_class_method def self.get_transactions(opts = {})
        bounds = scan_bounds(opts)
        raise ArgumentError, 'Range exceeds max_blocks; use scan_transactions and next_height' if bounds[:page_end] < opts[:end_height]

        result = scan_transactions(opts)
        raise RPCError.new(kind: 'incomplete scan; use scan_transactions for evidence'), cause: nil unless result[:complete]

        result[:transactions].map { |tx| tx[:txid] }
      end

      # Supported Method Parameters::
      # Scan address scripts in explicit blocks, not an arbitrary address index or wallet history.
      # PWN::Blockchain::BTC.scan_address_activity(
      #   address: 'required - Bitcoin address validated by the configured node',
      #   start_height: 'required - first nonnegative integer height; use next_height for continuation',
      #   end_height: 'required - final inclusive integer height; keep fixed across pages',
      #   max_blocks: 'optional - blocks examined per page, 1..1000; default 100',
      #   max_prevouts: 'optional - total parent RPC lookups per page, 0..1000; default 100',
      #   timeout: 'optional - per-RPC timeout seconds, 1..300; default 30'
      # )
      public_class_method def self.scan_address_activity(opts = {})
        address = opts[:address]
        raise ArgumentError, 'address must be an alphanumeric Bitcoin address' unless address.is_a?(String) && address.match?(/\A[a-zA-Z0-9]{14,90}\z/)

        bounds = scan_bounds(opts)
        budget = { remaining: integer_option(value: opts.fetch(:max_prevouts, 100), name: 'max_prevouts', range: 0..1000) }
        timeout = opts.fetch(:timeout, 30)
        validation = btc_rpc_call(method: 'validateaddress', params: [address], timeout: timeout)[:result]
        raise ArgumentError, 'address is invalid for the configured chain' unless validation[:isvalid] == true && validation[:scriptPubKey].is_a?(String)

        state = { activity: [], missing: [], cache: {}, budget: budget, script: validation[:scriptPubKey], timeout: timeout }
        on_block = ->(block) { address_block(block: block, state: state) }
        result = scan_page(bounds: bounds, verbosity: 3, timeout: timeout, on_block: on_block)
        result.merge(
          address: address, address_index: false, activity: state[:activity],
          missing_prevouts: state[:missing], complete: result[:complete] && state[:missing].empty?
        )
      end

      private_class_method def self.address_block(opts = {})
        block = opts[:block]
        state = opts[:state]
        block[:tx].each do |tx|
          state[:cache][tx[:txid]] = tx
          evidence = { txid: tx[:txid], blockhash: block[:hash], height: block[:height] }
          tx[:vout].each do |output|
            next unless output.dig(:scriptPubKey, :hex) == state[:script]

            state[:activity] << evidence.merge(type: :received, vout: output[:n], value_sats: satoshis(value: output[:value]))
          end
          tx[:vin].each_with_index do |input, index|
            next if input.key?(:coinbase)

            prevout, reason = resolve_prevout(input: input, cache: state[:cache], budget: state[:budget], timeout: state[:timeout])
            unless prevout
              state[:missing] << { txid: input[:txid], vout: input[:vout], spending_txid: tx[:txid], reason: reason }
              next
            end
            next unless prevout.dig(:scriptPubKey, :hex) == state[:script]

            state[:activity] << evidence.merge(type: :spent, vin: index, prev_txid: input[:txid], prev_vout: input[:vout], value_sats: satoshis(value: prevout[:value]))
          end
        end
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>
      public_class_method def self.authors
        'AUTHOR(S): 0day Inc. <support@0dayinc.com>'
      end

      # Display usage for this module.
      public_class_method def self.help
        puts "USAGE:
          # Return the legacy blockchain JSON-RPC envelope without AI analysis.
          #{self}.get_latest_block

          # Read chain synchronization and pruning status.
          #{self}.chain_status(timeout: 'optional - RPC timeout seconds, 1..300; default 30')

          # Read a block by height with Core verbosity.
          #{self}.get_block_details(
            height: 'optional - nonnegative integer height; default current tip',
            verbosity: 'optional - integer 0..3; default 1; 3 requires undo data',
            timeout: 'optional - RPC timeout seconds, 1..300; default 30'
          )

          # Inspect exact transaction amounts and fees only when all input values are known.
          #{self}.inspect_transaction(
            txid: 'required - 64-character hexadecimal transaction hash',
            blockhash: 'optional - containing block hash for root lookup without txindex',
            max_prevouts: 'optional - parent RPC lookup budget 0..1000; default 100',
            timeout: 'optional - per-RPC timeout seconds, 1..300; default 30'
          )

          # Check current UTXO membership; absence means spent or unknown, not proof of spending.
          #{self}.inspect_outpoint(
            txid: 'required - 64-character hexadecimal transaction hash',
            vout: 'required - nonnegative integer output index',
            include_mempool: 'optional - boolean include mempool effects; default true',
            timeout: 'optional - per-RPC timeout seconds, 1..300; default 30'
          )

          # Read aggregate mempool statistics without enumerating transactions.
          #{self}.mempool_summary(timeout: 'optional - per-RPC timeout seconds, 1..300; default 30')

          # Trace ancestor input references, not ownership, change, or later output allocation.
          #{self}.trace_transaction(
            txid: 'required - 64-character hexadecimal root transaction hash',
            blockhash: 'optional - containing block hash for root lookup without txindex',
            max_depth: 'optional - ancestor depth 0..100; default 3',
            max_transactions: 'optional - total transaction RPC budget 1..1000; default 100',
            max_edges: 'optional - evidence edge cap 1..10000; default 1000',
            timeout: 'optional - per-RPC timeout seconds, 1..300; default 30'
          )

          # Scan each explicit height for UTC dates; timestamps are not monotonic. Returns evidence and next_height.
          #{self}.scan_transactions(
            from: 'required - inclusive UTC date YYYY-MM-DD',
            to: 'required - inclusive UTC date YYYY-MM-DD',
            start_height: 'required - first nonnegative integer height; resume with next_height',
            end_height: 'required - final inclusive integer height; keep fixed across pages',
            max_blocks: 'optional - examined blocks per page 1..1000; default 100',
            timeout: 'optional - per-RPC timeout seconds, 1..300; default 30'
          )

          # Return the legacy ID array only for complete explicit height ranges; incomplete scans raise.
          #{self}.get_transactions(
            from: 'required - inclusive UTC date YYYY-MM-DD',
            to: 'required - inclusive UTC date YYYY-MM-DD',
            start_height: 'required - first nonnegative integer height',
            end_height: 'required - final inclusive integer height',
            max_blocks: 'optional - full range budget 1..1000; default 100; larger ranges require scan_transactions',
            timeout: 'optional - per-RPC timeout seconds, 1..300; default 30'
          )

          # Scan address scripts in explicit blocks; no arbitrary address index, balance or wallet history is implied.
          #{self}.scan_address_activity(
            address: 'required - Bitcoin address validated for the configured chain',
            start_height: 'required - first nonnegative integer height; resume with next_height',
            end_height: 'required - final inclusive integer height; keep fixed across pages',
            max_blocks: 'optional - examined blocks per page 1..1000; default 100',
            max_prevouts: 'optional - total parent RPC lookups per page 0..1000; default 100',
            timeout: 'optional - per-RPC timeout seconds, 1..300; default 30'
          )

          Scans return range-scoped completeness, missing evidence and chain anchors.
          Recheck anchor hashes across pages; no multi-call atomic snapshot is promised.
          Historical transaction lookups may require txindex; pruned data stays unavailable.
          Configuration: PWN::Env[:plugins][:blockchain][:bitcoin] with rpc_host,
          rpc_port, rpc_user, rpc_pass and optional rpc_scheme http or https.
          HTTPS verifies certificates. HTTP is plaintext; use only a trusted local channel.
          No prompts, AI, wallet mutation, broadcasting, or implicit full-chain scans.

          # Return author information.
          #{self}.authors
        "
      end
    end
  end
end
