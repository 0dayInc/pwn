# frozen_string_literal: true

require 'spec_helper'

describe PWN::Blockchain::ETH do
  let(:rpc_opts) { { rpc_url: 'https://node.example/secret' } }
  let(:address) { "0x#{'ab' * 20}" }
  let(:tx_hash) { "0x#{'cd' * 32}" }
  let(:transfer_topic) { '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef' }
  let(:transfer_log) do
    { address: address, topics: [transfer_topic, "0x#{'0' * 24}#{address[2..]}", "0x#{'0' * 64}"], data: "0x#{'0' * 63}7", blockNumber: '0x1', transactionHash: tx_hash }
  end

  it 'preserves BlockCypher APIs and token with verified TLS' do
    allow(RestClient::Request).to receive(:execute) do |request|
      expect(request[:verify_ssl]).to eq(OpenSSL::SSL::VERIFY_PEER)
      expect(request[:headers][:params]).to eq(token: 'token')
      double(body: '{"height":123}')
    end
    expect(described_class.get_latest_block(token: 'token')).to eq(height: 123)
    expect(described_class.get_block_details(height: 123, token: 'token')).to eq(height: 123)
    expect { described_class.get_block_details(height: '../bad') }.to raise_error(ArgumentError)
  end

  it 'redacts HTTP failures and JSON RPC provider messages including causes' do
    allow(RestClient::Request).to receive(:execute).and_raise(RestClient::Forbidden.new)
    expect { described_class.chain_status(rpc_opts) }.to raise_error(described_class::RPCError, 'Ethereum HTTP transport failed') { |error| expect(error.cause).to be_nil }
    allow(RestClient::Request).to receive(:execute).and_return(double(body: '{"jsonrpc":"2.0","id":1,"error":{"message":"secret"}}'))
    expect { described_class.chain_status(rpc_opts) }.to raise_error(described_class::RPCError, 'JSON-RPC provider returned an error')
  end

  it 'rejects bad envelopes, invalid quantities and invalid endpoints' do
    allow(RestClient::Request).to receive(:execute).and_return(double(body: 'not json'))
    expect { described_class.chain_status(rpc_opts) }.to raise_error(described_class::RPCError, /JSON response/)
    allow(RestClient::Request).to receive(:execute).and_return(double(body: '{"jsonrpc":"2.0","id":2,"result":1}'))
    expect { described_class.chain_status(rpc_opts) }.to raise_error(described_class::RPCError, /envelope/)
    stub_rpc('eth_chainId' => '0x01')
    expect { described_class.chain_status(rpc_opts) }.to raise_error(described_class::RPCError, /quantity/)
    expect { described_class.chain_status(rpc_url: 'file:///secret') }.to raise_error(ArgumentError)
  end

  it 'marks reverted receipts and does not infer success from inclusion alone' do
    stub_rpc('eth_getTransactionByHash' => { hash: tx_hash, value: '0x0', blockNumber: '0x1' },
             'eth_getTransactionReceipt' => { transactionHash: tx_hash, status: '0x0' })
    expect(described_class.transaction(rpc_opts.merge(hash: tx_hash))[:status]).to eq(:reverted)
    stub_rpc('eth_getTransactionByHash' => { hash: tx_hash, value: '0x0', blockNumber: '0x1' }, 'eth_getTransactionReceipt' => nil)
    expect(described_class.transaction(rpc_opts.merge(hash: tx_hash))[:status]).to eq(:receipt_unavailable)
  end

  it 'decodes only standard Transfer layouts without claiming contract conformance' do
    expect(described_class.decode_transfer(log: transfer_log)).to include(standard: :erc20, value: 7, from: address)
    nft = transfer_log.merge(topics: transfer_log[:topics] + ["0x#{'0' * 63}9"], data: '0x')
    expect(described_class.decode_transfer(log: nft)).to include(standard: :erc721, token_id: 9)
    expect(described_class.decode_transfer(log: transfer_log.merge(topics: [tx_hash]))).to be_nil
    expect { described_class.decode_transfer(log: transfer_log.merge(data: '0x01')) }.to raise_error(ArgumentError)
    expect { described_class.decode_transfer(log: transfer_log.merge(topics: [transfer_topic, tx_hash, tx_hash])) }.to raise_error(ArgumentError)
  end

  it 'bounds logs and reports local truncation without provider completeness guarantees' do
    stub_rpc('eth_getLogs' => [transfer_log, transfer_log])
    result = described_class.event_logs(rpc_opts.merge(from_block: 1, to_block: 2, limit: 1))
    expect(result).to include(truncated: true, complete: false, provider_completeness: :unverified)
    expect(result[:logs].length).to eq(1)
    expect { described_class.event_logs(rpc_opts.merge(from_block: 0, to_block: 10_001)) }.to raise_error(ArgumentError)
  end

  it 'paginates address activity by whole blocks and excludes traces explicitly' do
    stub_rpc('eth_getBlockByNumber' => { number: '0x1', hash: tx_hash, transactions: [{ hash: tx_hash, from: address, to: nil, value: '0x1' }] })
    result = described_class.address_activity(rpc_opts.merge(address: address, from_block: 1, to_block: 2, page_size: 1))
    expect(result).to include(next_block: 2, complete: false, internal_traces: :not_covered)
    expect(result[:transactions].length).to eq(1)
  end

  it 'rejects malformed unknown-event topics and out-of-range provider logs' do
    stub_rpc('eth_getLogs' => [transfer_log.merge(topics: ['0xbad'])])
    expect { described_class.event_logs(rpc_opts.merge(from_block: 1, to_block: 2)) }.to raise_error(ArgumentError)
    stub_rpc('eth_getLogs' => [transfer_log.merge(blockNumber: '0x3')])
    expect { described_class.event_logs(rpc_opts.merge(from_block: 1, to_block: 2)) }.to raise_error(described_class::RPCError)
  end

  it 'redacts malformed legacy response bodies and timeout details' do
    allow(RestClient::Request).to receive(:execute).and_return(double(body: 'secret-invalid-json'))
    expect { described_class.get_latest_block }.to raise_error(described_class::RPCError, 'Invalid BlockCypher JSON response') { |error| expect(error.cause).to be_nil }
    allow(RestClient::Request).to receive(:execute).and_raise(Timeout::Error, 'https://node.example/secret')
    expect { described_class.chain_status(rpc_opts) }.to raise_error(described_class::RPCError, 'Ethereum HTTP transport failed')
  end

  it 'rejects mismatched block identities and receipt inclusion contexts' do
    stub_rpc('eth_getBlockByNumber' => { number: '0x2', hash: tx_hash })
    expect { described_class.block(rpc_opts.merge(block: 1)) }.to raise_error(described_class::RPCError)
    stub_rpc('eth_getTransactionByHash' => { hash: tx_hash, value: '0x0', blockNumber: '0x1', blockHash: tx_hash },
             'eth_getTransactionReceipt' => { transactionHash: tx_hash, status: '0x1', blockNumber: '0x2', blockHash: tx_hash })
    expect { described_class.transaction(rpc_opts.merge(hash: tx_hash)) }.to raise_error(described_class::RPCError)
  end

  it 'resumes activity without duplicates and states when the requested range is exhausted' do
    allow(RestClient::Request).to receive(:execute) do |request|
      payload = JSON.parse(request[:payload])
      height = payload['params'][0]
      double(body: JSON.generate(jsonrpc: '2.0', id: 1, result: { number: height, hash: tx_hash, transactions: [] }))
    end
    page = described_class.address_activity(rpc_opts.merge(address: address, from_block: 1, to_block: 2, page_size: 1))
    last = described_class.address_activity(rpc_opts.merge(address: address, from_block: page[:next_block], to_block: 2, page_size: 1))
    expect(last).to include(complete: true, next_block: nil, from_block: 2)
  end

  it 'reads token metadata at a common block with optional unsupported fields' do
    allow(RestClient::Request).to receive(:execute) do |request|
      payload = JSON.parse(request[:payload])
      result = if payload['method'] == 'eth_getBlockByNumber'
                 { number: '0x1', hash: tx_hash }
               else
                 expect(payload['params'][1]).to eq('blockHash' => tx_hash, 'requireCanonical' => true)
                 case payload['params'][0]['data']
                 when '0x313ce567' then "0x#{18.to_s(16).rjust(64, '0')}"
                 when '0x18160ddd' then "0x#{'f' * 64}"
                 when '0x95d89b41' then "0x#{'TOK'.unpack1('H*').ljust(64, '0')}"
                 else '0x'
                 end
               end
      double(body: JSON.generate(jsonrpc: '2.0', id: 1, result: result))
    end
    result = described_class.token_metadata(rpc_opts.merge(contract: address))
    expect(result).to include(decimals: 18, symbol: 'TOK', total_supply: (2**256) - 1, name: nil)
    expect(result[:unavailable]).to include(:name)
  end

  it 'performs a pinned read-only contract call with exact byte output' do
    stub_rpc('eth_getBlockByNumber' => { number: '0x1', hash: tx_hash }, 'eth_call' => '0x0001')
    expect(described_class.call(rpc_opts.merge(contract: address, data: '0x18160ddd'))).to include(data: '0x0001', block_hash: tx_hash)
  end

  it 'inspects a mined transaction with exact execution and blob fees' do
    stub_rpc('eth_getTransactionByHash' => { hash: tx_hash, from: address, to: nil, value: '0x20000000000001', blockNumber: '0x10' },
             'eth_getTransactionReceipt' => { transactionHash: tx_hash, status: '0x1', gasUsed: '0x5208', effectiveGasPrice: '0x100000000', blobGasUsed: '0x2', blobGasPrice: '0x3', contractAddress: address })
    result = described_class.transaction(rpc_opts.merge(hash: tx_hash))
    expect(result).to include(status: :success, value_wei: 9_007_199_254_740_993, execution_fee_wei: 90_194_313_216_000, blob_fee_wei: 6, contract_address: address, internal_traces: :not_covered)
  end

  it 'distinguishes pending and unknown transactions' do
    stub_rpc('eth_getTransactionByHash' => { hash: tx_hash, value: '0x0', blockNumber: nil }, 'eth_getTransactionReceipt' => nil)
    expect(described_class.transaction(rpc_opts.merge(hash: tx_hash))[:status]).to eq(:pending)
    stub_rpc('eth_getTransactionByHash' => nil)
    expect(described_class.transaction(rpc_opts.merge(hash: tx_hash))[:status]).to eq(:not_found)
  end

  it 'reads a block by hash and an account at an explicit block context' do
    stub_rpc('eth_getBlockByHash' => { hash: tx_hash, number: '0x10' },
             'eth_getBlockByNumber' => { hash: tx_hash, number: '0x10' },
             'eth_getBalance' => '0x20000000000001', 'eth_getTransactionCount' => '0x3', 'eth_getCode' => '0x6000')
    expect(described_class.block(rpc_opts.merge(block: tx_hash))[:block][:hash]).to eq(tx_hash)
    expect(described_class.account(rpc_opts.merge(address: address))).to include(balance_wei: 9_007_199_254_740_993, nonce: 3, code: '0x6000', block_number: 16, block_hash: tx_hash)
  end

  it 'rejects malformed identifiers before transport' do
    expect(RestClient::Request).not_to receive(:execute)
    expect { described_class.transaction(rpc_opts.merge(hash: '0xabc')) }.to raise_error(ArgumentError)
    expect { described_class.account(rpc_opts.merge(address: "#{address} ")) }.to raise_error(ArgumentError)
    expect { described_class.block(rpc_opts.merge(block: -1)) }.to raise_error(ArgumentError)
  end

  def stub_rpc(results)
    allow(RestClient::Request).to receive(:execute) do |request|
      payload = JSON.parse(request[:payload])
      expect(request[:method]).to eq(:post)
      expect(request[:max_redirects]).to eq(0)
      expect(request[:timeout]).to eq(30)
      expect(request[:verify_ssl]).to eq(OpenSSL::SSL::VERIFY_PEER)
      expect(request[:open_timeout]).to eq(10)
      result = results.fetch(payload.fetch('method'))
      double(body: JSON.generate(jsonrpc: '2.0', id: 1, result: result))
    end
  end

  it 'reads chain status through verified read-only JSON RPC' do
    stub_rpc('eth_chainId' => '0x1', 'eth_blockNumber' => '0x123', 'eth_syncing' => false)
    expect(described_class.chain_status(rpc_opts)).to include(chain_id: 1, block_number: 291, syncing: false)
  end

  it 'validates dynamic ABI string bounds and padding' do
    words = [32, 3].map { |value| value.to_s(16).rjust(64, '0') }.join
    dynamic = "0x#{words}#{'TOK'.unpack1('H*').ljust(64, '0')}"
    stub_rpc('eth_getBlockByNumber' => { number: '0x1', hash: tx_hash }, 'eth_call' => dynamic)
    expect(described_class.token_metadata(rpc_opts.merge(contract: address))).to include(name: 'TOK', symbol: 'TOK', decimals: nil)
    stub_rpc('eth_getBlockByNumber' => { number: '0x1', hash: tx_hash }, 'eth_call' => "#{dynamic[0...-1]}1")
    expect(described_class.token_metadata(rpc_opts.merge(contract: address))[:unavailable]).to include(:name, :symbol)
  end

  it 'rejects transport redirects, TLS failures and missing results without revealing endpoints' do
    [RestClient::MovedPermanently.new, OpenSSL::SSL::SSLError.new('secret endpoint')].each do |error|
      allow(RestClient::Request).to receive(:execute).and_raise(error)
      expect { described_class.chain_status(rpc_opts) }.to raise_error(described_class::RPCError, 'Ethereum HTTP transport failed') { |failure| expect(failure.cause).to be_nil }
    end
    allow(RestClient::Request).to receive(:execute).and_return(double(body: '{"jsonrpc":"2.0","id":1}'))
    expect { described_class.chain_status(rpc_opts) }.to raise_error(described_class::RPCError, 'Missing JSON-RPC result')
  end

  it 'validates numeric boundaries and filters before issuing requests' do
    expect(RestClient::Request).not_to receive(:execute)
    expect { described_class.chain_status(rpc_opts.merge(timeout: 0)) }.to raise_error(ArgumentError)
    expect { described_class.block(rpc_opts.merge(block: '0x01')) }.to raise_error(ArgumentError)
    expect { described_class.event_logs(rpc_opts.merge(from_block: 2, to_block: 1)) }.to raise_error(ArgumentError)
    expect { described_class.event_logs(rpc_opts.merge(from_block: 1, to_block: 1, topics: ['0x1'])) }.to raise_error(ArgumentError)
    expect { described_class.address_activity(rpc_opts.merge(address: address, from_block: 1, to_block: 2, page_size: 101)) }.to raise_error(ArgumentError)
  end

  it 'includes every public API in usable help' do
    expect { described_class.help }.to output(/token_metadata.*get_latest_block/m).to_stdout
  end

  it 'should display information for authors' do
    authors_response = PWN::Blockchain::ETH
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Blockchain::ETH
    expect(help_response).to respond_to :help
  end
end
