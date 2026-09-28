# frozen_string_literal: true

require 'spec_helper'

describe PWN::Blockchain::BTC do # rubocop:disable Metrics/BlockLength
  let(:config) { { rpc_host: 'localhost', rpc_port: 8332, rpc_user: 'alice', rpc_pass: 'secret' }.freeze }
  let(:http) { instance_double(Net::HTTP) }

  before do
    stub_const('PWN::Env', { plugins: { blockchain: { bitcoin: config } } })
    allow(Net::HTTP).to receive(:new).and_return(http)
    allow(http).to receive(:open_timeout=)
    allow(http).to receive(:read_timeout=)
    allow(http).to receive(:write_timeout=)
    allow(http).to receive(:use_ssl=)
    allow(http).to receive(:verify_mode=)
  end

  def rpc_response(result: nil, error: nil, status: '200')
    double('response', code: status, body: JSON.generate(result: result, error: error, id: 'pwn-btc'))
  end

  it 'returns the legacy envelope silently without AI or config mutation' do
    allow(http).to receive(:request).and_return(rpc_response(result: { blocks: 10 }))
    expect { expect(described_class.get_latest_block[:result]).to eq(blocks: 10) }.not_to output.to_stdout
  end

  it 'preserves HTTP 500 RPC error codes without echoing server secrets' do
    allow(http).to receive(:request).and_return(rpc_response(error: { code: -5, message: 'secret alice' }, status: '500'))
    expect { described_class.get_latest_block }.to raise_error(described_class::RPCError) { |e|
      expect(e.code).to eq(-5)
      expect(e.http_status).to eq(500)
      expect(e.message).not_to include('secret', 'alice')
    }
  end

  it 'uses verified TLS, bounded timeouts and authenticated POST' do
    config = self.config.merge(rpc_scheme: 'https')
    stub_const('PWN::Env', { plugins: { blockchain: { bitcoin: config } } })
    expect(http).to receive(:use_ssl=).with(true)
    expect(http).to receive(:verify_mode=).with(OpenSSL::SSL::VERIFY_PEER)
    expect(http).to receive(:read_timeout=).with(30)
    expect(http).to receive(:request) do |request|
      expect(request).to be_a(Net::HTTP::Post)
      expect(JSON.parse(request.body)['method']).to eq('getblockchaininfo')
      rpc_response(result: { blocks: 0 })
    end
    described_class.get_latest_block
  end

  it 'sanitizes transport failures and suppresses their causes' do
    allow(http).to receive(:request).and_raise(IOError, 'secret alice')
    expect { described_class.get_latest_block }.to raise_error(described_class::RPCError) { |e|
      expect(e.message).not_to include('secret', 'alice')
      expect(e.cause).to be_nil
    }
  end
  let(:txid) { 'a' * 64 }
  let(:parent_id) { 'b' * 64 }
  let(:blockhash) { 'c' * 64 }
  let(:parent_tx) { { txid: parent_id, vin: [{ coinbase: '00' }], vout: [{ n: 0, value: '0.10000001', scriptPubKey: { address: 'test' } }] } }
  let(:transaction) { { txid: txid, vin: [{ txid: parent_id, vout: 0 }], vout: [{ n: 0, value: '0.10000000', scriptPubKey: { address: 'test' } }] } }

  def serve_rpc(&block)
    allow(http).to receive(:request) do |request|
      payload = JSON.parse(request.body, symbolize_names: true)
      result = block.call(payload[:method], payload[:params])
      rpc_response(result: result)
    end
  end

  it 'inspects exact satoshis, resolves prevouts and computes fees only with evidence' do
    serve_rpc do |method, params|
      expect(method).to eq('getrawtransaction')
      params.first == txid ? transaction : parent_tx
    end
    result = described_class.inspect_transaction(txid: txid)
    expect(result[:outputs].first[:value_sats]).to eq(10_000_000)
    expect(result[:inputs].first[:value_sats]).to eq(10_000_001)
    expect(result[:fee_sats]).to eq(1)
    expect(result[:missing_prevouts]).to be_empty
  end

  it 'reports unavailable prevouts, does not invent fees and bounds lookups' do
    serve_rpc { transaction }
    result = described_class.inspect_transaction(txid: txid, max_prevouts: 0)
    expect(result[:fee_sats]).to be_nil
    expect(result[:missing_prevouts]).to eq([{ txid: parent_id, vout: 0, reason: :lookup_limit }])
    expect(http).to have_received(:request).once
  end

  it 'passes an optional block hash for non-indexed transaction lookup' do
    serve_rpc do |_method, params|
      expect(params).to eq([txid, true, blockhash])
      transaction.merge(vin: [{ coinbase: '00' }])
    end
    result = described_class.inspect_transaction(txid: txid, blockhash: blockhash)
    expect(result[:coinbase]).to be(true)
    expect(result[:fee_sats]).to be_nil
  end

  it 'does not hide authentication errors as missing transactions' do
    allow(http).to receive(:request).and_return(rpc_response(result: transaction), rpc_response(error: { code: -32_600 }, status: '401'))
    expect { described_class.inspect_transaction(txid: txid) }.to raise_error(described_class::RPCError)
  end

  it 'inspects an unspent outpoint and distinguishes null from proof of spending' do
    serve_rpc do |method, params|
      expect(method).to eq('gettxout')
      expect(params).to eq([txid, 0, false])
      { value: '0.00000001', confirmations: 4 }
    end
    expect(described_class.inspect_outpoint(txid: txid, vout: 0, include_mempool: false)[:value_sats]).to eq(1)
    serve_rpc { nil }
    expect(described_class.inspect_outpoint(txid: txid, vout: 0)).to include(status: :spent_or_unknown, unspent: false)
  end

  it 'reads mempool statistics without fetching all transactions' do
    serve_rpc do |method, params|
      expect([method, params]).to eq(['getmempoolinfo', []])
      { size: 10, bytes: 2345, loaded: true }
    end
    expect(described_class.mempool_summary[:size]).to eq(10)
  end

  it 'rejects malformed identifiers, indices and flags before issuing RPC' do
    expect(http).not_to receive(:request)
    expect { described_class.inspect_transaction(txid: 'bad') }.to raise_error(ArgumentError)
    expect { described_class.inspect_outpoint(txid: txid, vout: '0') }.to raise_error(ArgumentError)
    expect { described_class.inspect_outpoint(txid: txid, vout: 0, include_mempool: 'false') }.to raise_error(ArgumentError)
    expect { described_class.get_block_details(height: -1) }.to raise_error(ArgumentError)
    expect { described_class.get_block_details(height: 0, verbosity: 4) }.to raise_error(ArgumentError)
  end

  it 'traces ancestors with spend-reference evidence and exact values' do
    serve_rpc { |_method, params| params.first == txid ? transaction : parent_tx }
    result = described_class.trace_transaction(txid: txid)
    expect(result[:nodes].map { |node| node[:txid] }).to eq([txid, parent_id])
    expect(result[:edges]).to eq([{ from_txid: parent_id, from_vout: 0, to_txid: txid, to_vin: 0, value_sats: 10_000_001, evidence: :vin_reference }])
    expect(result[:complete]).to be(true)
    expect(http).to have_received(:request).twice
  end

  it 'reports depth and transaction limits without fetching beyond either bound' do
    serve_rpc { transaction }
    result = described_class.trace_transaction(txid: txid, max_depth: 0)
    expect(result).to include(complete: false, truncated: true)
    expect(result[:truncation_reasons]).to include(:max_depth)
    expect(result[:missing_prevouts].first).to include(txid: parent_id, vout: 0)
    expect(http).to have_received(:request).once
  end

  it 'bounds edges and reports omitted input evidence explicitly' do
    serve_rpc { transaction.merge(vin: [{ txid: parent_id, vout: 0 }, { txid: parent_id, vout: 1 }]) }
    result = described_class.trace_transaction(txid: txid, max_edges: 1, max_transactions: 1)
    expect(result[:edges].length).to eq(1)
    expect(result[:truncation_reasons]).to include(:max_edges, :max_transactions)
    expect(http).to have_received(:request).once
  end

  it 'reports unavailable ancestors rather than claiming a complete trace' do
    allow(http).to receive(:request).and_return(rpc_response(result: transaction), rpc_response(error: { code: -5 }, status: '500'))
    result = described_class.trace_transaction(txid: txid)
    expect(result[:complete]).to be(false)
    expect(result[:missing_transactions]).to eq([{ txid: parent_id, code: -5 }])
    expect(result[:missing_prevouts].first[:reason]).to eq(:unavailable)
  end

  def serve_chain(times:, transactions: nil, reorg: false)
    anchor_reads = 0
    serve_rpc do |method, params|
      case method
      when 'getblockchaininfo' then { blocks: times.length - 1, bestblockhash: blockhash, chain: 'regtest' }
      when 'getblockhash'
        anchor_reads += 1 if params.first == times.length - 1
        reorg && anchor_reads > 2 ? 'f' * 64 : format('%064x', params.first)
      when 'getblock'
        height = params.first.to_i(16)
        { hash: params.first, height: height, previousblockhash: format('%064x', height - 1), time: times[height], tx: transactions || [format('%064x', height + 100)] }
      when 'validateaddress' then { isvalid: true, scriptPubKey: '76a91400' }
      else raise "Unexpected RPC #{method}"
      end
    end
  end

  it 'scans every explicit height despite nonmonotonic timestamps and uses UTC days' do
    serve_chain(times: [1_704_067_200, 1_704_240_000, 1_704_067_210])
    result = described_class.scan_transactions(from: '2024-01-01', to: '2024-01-01', start_height: 0, end_height: 2)
    expect(result[:transactions].map { |tx| tx[:height] }).to eq([0, 2])
    expect(result).to include(complete: true, next_height: nil, reorg_detected: false)
    expect(result[:blocks].length).to eq(3)
    expect(result[:scope]).to eq(:explicit_height_range)
  end

  it 'returns bounded pages with explicit continuation instead of silently omitting dates' do
    serve_chain(times: [1_704_067_200] * 3)
    result = described_class.scan_transactions(from: '2024-01-01', to: '2024-01-01', start_height: 0, end_height: 2, max_blocks: 1)
    expect(result).to include(complete: false, truncated: true, next_height: 1)
    expect(result[:transactions].length).to eq(1)
  end

  it 'preserves the legacy array only for a fully scanned explicit range' do
    serve_chain(times: [1_704_067_200])
    expect(described_class.get_transactions(from: '2024-01-01', to: '2024-01-01', start_height: 0, end_height: 0)).to eq([format('%064x', 100)])
    expect { described_class.get_transactions(from: '2024-01-01', to: '2024-01-01') }.to raise_error(ArgumentError)
    expect { described_class.get_transactions(from: '2024-01-01', to: '2024-01-01', start_height: 0, end_height: 2, max_blocks: 1) }.to raise_error(ArgumentError)
  end

  it 'detects anchor changes and never labels reorganized scans complete' do
    serve_chain(times: [1_704_067_200], reorg: true)
    result = described_class.scan_transactions(from: '2024-01-01', to: '2024-01-01', start_height: 0, end_height: 0)
    expect(result).to include(reorg_detected: true, complete: false)
  end

  it 'requires strict dates and explicit integer height ranges before RPC' do
    expect(http).not_to receive(:request)
    expect { described_class.scan_transactions(from: '2024-02-30', to: '2024-03-01', start_height: 0, end_height: 1) }.to raise_error(ArgumentError)
    expect { described_class.scan_transactions(from: '2024-01-02', to: '2024-01-01', start_height: 0, end_height: 1) }.to raise_error(ArgumentError)
    expect { described_class.scan_transactions(from: '2024-01-01', to: '2024-01-01') }.to raise_error(ArgumentError)
  end

  it 'scans address scripts with receive and spend evidence, not an address index' do
    parent = parent_tx.merge(vout: [{ n: 0, value: '0.10000001', scriptPubKey: { hex: '76a91400' } }])
    spend = transaction.merge(vout: [{ n: 0, value: '0.10000000', scriptPubKey: { hex: 'other' } }])
    serve_chain(times: [1_704_067_200], transactions: [parent, spend])
    result = described_class.scan_address_activity(address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', start_height: 0, end_height: 0, max_prevouts: 0)
    expect(result[:activity].map { |event| event[:type] }).to eq(%i[received spent])
    expect(result[:activity].map { |event| event[:value_sats] }).to eq([10_000_001, 10_000_001])
    expect(result[:complete]).to be(true)
    expect(result[:address_index]).to be(false)
  end

  it 'uses undo-rich blocks without spending the available parent lookup budget' do
    prevout = { value: '0.10000001', scriptPubKey: { hex: '76a91400' } }
    spend = transaction.merge(vin: [{ txid: parent_id, vout: 0, prevout: prevout }])
    serve_chain(times: [1_704_067_200], transactions: [spend])
    expect(described_class).to receive(:get_block_details).with({ height: 0, verbosity: 3, timeout: 30 }).and_call_original
    result = described_class.scan_address_activity(address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', start_height: 0, end_height: 0, max_prevouts: 5)
    expect(result).to include(complete: true, missing_prevouts: [])
    expect(result[:activity]).to include(include(type: :spent, value_sats: 10_000_001, prev_txid: parent_id))
    expect(http).to have_received(:request).exactly(7).times
  end

  [-8, -32_602].each do |code|
    it "falls back to verbosity 2 for older-node parameter error #{code}" do
      parent = parent_tx.merge(vout: [{ n: 0, value: '0.10000001', scriptPubKey: { hex: '76a91400' } }])
      serve_chain(times: [1_704_067_200], transactions: [parent, transaction])
      allow(described_class).to receive(:btc_rpc_call).and_wrap_original do |original, opts|
        raise described_class::RPCError.new(rpc_method: 'getblock', code: code, http_status: 500) if opts[:method] == 'getblock' && opts[:params].last == 3

        original.call(opts)
      end
      result = described_class.scan_address_activity(address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', start_height: 0, end_height: 0, max_prevouts: 0)
      expect(result).to include(complete: true, missing_prevouts: [])
      expect(result[:activity].map { |event| event[:type] }).to eq(%i[received spent])
      expect(described_class).to have_received(:btc_rpc_call).with(method: 'getblock', params: [format('%064x', 0), 2], timeout: 30).once
    end
  end

  it 'does not downgrade unavailable undo data into a successful address scan' do
    serve_chain(times: [1_704_067_200], transactions: [transaction])
    allow(described_class).to receive(:btc_rpc_call).and_wrap_original do |original, opts|
      if opts[:method] == 'getblock'
        expect(opts[:params].last).to eq(3)
        raise described_class::RPCError.new(rpc_method: 'getblock', code: -1, http_status: 500)
      end

      original.call(opts)
    end
    result = described_class.scan_address_activity(address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', start_height: 0, end_height: 0)
    expect(result).to include(complete: false, missing_blocks: [{ height: 0, code: -1 }])
  end

  it 'reports unknown address spends when parent data is missing' do
    serve_chain(times: [1_704_067_200], transactions: [transaction])
    result = described_class.scan_address_activity(address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', start_height: 0, end_height: 0, max_prevouts: 0)
    expect(result[:complete]).to be(false)
    expect(result[:missing_prevouts].first).to include(txid: parent_id, reason: :lookup_limit)
  end

  it 'accepts uppercase hashes without losing trace evidence or rewriting the RPC token' do
    serve_rpc do |_method, params|
      expect(params.first).to eq(txid.upcase)
      transaction
    end
    result = described_class.trace_transaction(txid: txid.upcase, max_depth: 0)
    expect(result[:edges].first[:to_txid]).to eq(txid)
  end

  it 'decodes JSON numeric amounts without a Float roundtrip' do
    body = JSON.generate(result: transaction.merge(vin: [{ coinbase: '00' }]), error: nil, id: 'pwn-btc').sub('"0.10000000"', '20999999.99999999')
    allow(http).to receive(:request).and_return(double('response', code: '200', body: body))
    expect(described_class.inspect_transaction(txid: txid)[:output_sats]).to eq(2_099_999_999_999_999)
  end

  it 'rejects sub-satoshi values rather than rounding them' do
    bad = transaction.merge(vin: [{ coinbase: '00' }], vout: [{ n: 0, value: '0.000000001' }])
    serve_rpc { bad }
    expect { described_class.inspect_transaction(txid: txid) }.to raise_error(described_class::RPCError, /invalid monetary/)
  end

  it 'reuses a single parent lookup across several inputs' do
    parent = parent_tx.merge(vout: [{ n: 0, value: '0.10000001' }, { n: 1, value: '0.2' }])
    spend = transaction.merge(vin: [{ txid: parent_id, vout: 0 }, { txid: parent_id, vout: 1 }])
    serve_rpc { |_method, params| params.first == txid ? spend : parent }
    expect(described_class.inspect_transaction(txid: txid, max_prevouts: 1)[:input_sats]).to eq(30_000_001)
    expect(http).to have_received(:request).twice
  end

  it 'returns pruning gaps as incomplete date evidence and raises in legacy array mode' do
    serve_chain(times: [1_704_067_200])
    allow(described_class).to receive(:get_block_details).and_raise(described_class::RPCError.new(code: -1, http_status: 500))
    opts = { from: '2024-01-01', to: '2024-01-01', start_height: 0, end_height: 0 }
    result = described_class.scan_transactions(opts)
    expect(result).to include(complete: false, missing_blocks: [{ height: 0, code: -1 }])
    expect { described_class.get_transactions(opts) }.to raise_error(described_class::RPCError, /incomplete scan/)
  end

  it 'returns block serialization or transaction verbosity as explicitly requested' do
    [0, 1, 2, 3].each do |verbosity|
      serve_rpc do |method, params|
        if method == 'getblockhash'
          expect(params).to eq([0])
          blockhash
        else
          expect(params).to eq([blockhash, verbosity])
          verbosity.zero? ? 'deadbeef' : { hash: blockhash, tx: [] }
        end
      end
      result = described_class.get_block_details(height: 0, verbosity: verbosity)
      expect(result).to eq(verbosity.zero? ? 'deadbeef' : { hash: blockhash, tx: [] })
    end
  end

  it 'rejects malformed JSON, mismatched IDs and non-JSON HTTP failures without leaking bodies' do
    ['secret alice', '{"id":"other","result":"secret"}', '[]'].each do |body|
      allow(http).to receive(:request).and_return(double('response', code: '503', body: body))
      expect { described_class.get_latest_block }.to raise_error(described_class::RPCError) { |e|
        expect(e.http_status).to eq(503)
        expect(e.message).not_to include('secret', 'alice')
        expect(e.cause).to be_nil
      }
    end
  end

  it 'rejects absent credentials, unsafe hosts, invalid ports and timeouts without connecting' do
    expect(http).not_to receive(:request)
    [config.merge(rpc_pass: nil), config.merge(rpc_host: 'http://secret@host'), config.merge(rpc_port: '8332oops')].each do |invalid|
      stub_const('PWN::Env', { plugins: { blockchain: { bitcoin: invalid.freeze } } })
      expect { described_class.get_latest_block }.to raise_error(ArgumentError)
    end
    stub_const('PWN::Env', { plugins: { blockchain: { bitcoin: config } } })
    expect { described_class.chain_status(timeout: 0) }.to raise_error(ArgumentError)
    expect { described_class.chain_status(timeout: '30') }.to raise_error(ArgumentError)
  end

  it 'rejects write RPCs even at the private transport boundary' do
    expect(http).not_to receive(:request)
    expect { described_class.send(:btc_rpc_call, method: 'sendrawtransaction', params: ['00']) }.to raise_error(ArgumentError)
  end

  it 'sanitizes connection setup exceptions as well as request failures' do
    allow(Net::HTTP).to receive(:new).and_raise(IOError, 'secret alice')
    expect { described_class.get_latest_block }.to raise_error(described_class::RPCError) { |e|
      expect(e.message).not_to include('secret', 'alice')
      expect(e.cause).to be_nil
    }
  end

  it 'enforces a total request deadline even when a peer keeps dribbling data' do
    allow(http).to receive(:request) { sleep 2 }
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    expect { described_class.chain_status(timeout: 1) }.to raise_error(described_class::RPCError, /transport/)
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 1.8
  end

  it 'should display information for authors' do
    authors_response = PWN::Blockchain::BTC
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Blockchain::BTC
    expect(help_response).to respond_to :help
  end
end
