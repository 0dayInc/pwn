# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'

RSpec.describe PWN::WWW::HackerOne, 'pagination review consistency' do
  before do
    stub_const('PWN::Env', { ai: { module_reflection: false } })
    @requests = []
    @pages = []
    # Exercise the real TransparentBrowser, Request serialization and Response
    # decoding. Only transmission is synthetic: no provider is contacted.
    allow_any_instance_of(RestClient::Request).to receive(:transmit) do |request, _uri, _http, payload|
      @requests << { tls: request.verify_ssl, body: JSON.parse(payload.to_s) }
      page = @pages.shift || raise('unexpected request beyond supplied pages')
      RestClient::Response.create(JSON.generate(page), Net::HTTPOK.new('1.1', '200', 'OK'), request)
    end
  end

  def page_for(method, ids, total, has_next)
    search = { nodes: ids.map { |id| { id: id.to_s } }, total_count: total }
    if method == :get_scope_details
      search[:pageInfo] = { hasNextPage: has_next }
      { data: { team: { structured_scopes_search: search } } }
    else
      { data: { search: search } }
    end
  end

  %i[get_scope_details get_hacktivity].each do |method|
    it "SERVICES-REVIEW-008 returns all 201 unique records across three real serialized #{method} requests" do
      @pages = (0...201).each_slice(100).with_index.map { |ids, i| page_for(method, ids, 201, i < 2) }
      options = { program_name: 'fixture' }.freeze
      result = described_class.public_send(method, options)
      search = if method == :get_scope_details
                 result[:scope_details][:data][:team][:structured_scopes_search]
               else
                 result[:hacktivity][:data][:search]
               end

      expect(search[:nodes].map { |node| node[:id] }).to eq((0...201).map(&:to_s))
      expect(search[:nodes].map { |node| node[:id] }.uniq.length).to eq(search[:total_count])
      expect(@requests.map { |req| req[:body]['variables']['from'] }).to eq([0, 100, 200])
      expect(@requests.map { |req| req[:tls] }).to eq([OpenSSL::SSL::VERIFY_PEER] * 3)
      expect(@pages).to eq([])
      expect(options).to eq(program_name: 'fixture')
    end

    it "SERVICES-REVIEW-008 rejects #{method} records exceeding the declared total" do
      @pages = [page_for(method, %w[one two], 1, false)]

      expect { described_class.public_send(method, program_name: 'fixture') }.to raise_error(RuntimeError, /pagination.*count/)
      expect(@requests.length).to eq(1)
    end

    it "SERVICES-REVIEW-008 signals changing #{method} totals rather than claiming a complete stable result" do
      @pages = [page_for(method, ['one'], 2, true), page_for(method, %w[two three], 3, false)]

      expect { described_class.public_send(method, program_name: 'fixture') }.to raise_error(RuntimeError, /pagination.*total_count/)
      expect(@requests.length).to eq(2)
    end

    it "SERVICES-REVIEW-008 accepts a consistent empty #{method} result" do
      @pages = [page_for(method, [], 0, false)]

      expect { described_class.public_send(method, program_name: 'fixture') }.not_to raise_error
      expect(@requests.length).to eq(1)
    end
  end

  it 'SERVICES-REVIEW-008 rejects a short final scope page inconsistent with total_count' do
    @pages = [page_for(:get_scope_details, ['one'], 2, false)]

    expect { described_class.get_scope_details(program_name: 'fixture') }.to raise_error(RuntimeError, /pagination.*count/)
    expect(@requests.length).to eq(1)
  end

  it 'SERVICES-REVIEW-008 rejects hasNextPage when the declared scope total has already been reached' do
    @pages = [page_for(:get_scope_details, ['one'], 1, true), page_for(:get_scope_details, [], 1, false)]

    expect { described_class.get_scope_details(program_name: 'fixture') }.to raise_error(RuntimeError, /pagination.*count/)
    expect(@requests.length).to eq(1)
  end
end
