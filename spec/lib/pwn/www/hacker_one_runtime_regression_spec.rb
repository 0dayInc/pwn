# frozen_string_literal: true

require 'spec_helper'
require 'rest-client'
require 'open3'
require 'tmpdir'

RSpec.describe PWN::WWW::HackerOne, 'GraphQL runtime regressions' do
  let(:handle) { { browser: RestClient, type: :rest } }

  before do
    stub_const('PWN::Env', { ai: { module_reflection: false } })
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(handle)
    allow(PWN::Plugins::TransparentBrowser).to receive(:close).and_return(nil)
    allow(PWN::AI::Agent::HackerOne).to receive(:analyze).and_return(nil)
  end

  %i[get_bounty_programs get_scope_details get_hacktivity].each do |method|
    it "validates TLS for #{method}" do
      response = { data: {
        teams: { edges: [], pageInfo: { hasNextPage: false } },
        team: { structured_scopes_search: { nodes: [], total_count: 0, pageInfo: { hasNextPage: false } } },
        search: { nodes: [], total_count: 0 }
      } }
      expect(RestClient::Request).to receive(:execute) do |options|
        expect(options[:verify_ssl]).to be(true)
        instance_double(RestClient::Response, body: response.to_json)
      end
      described_class.public_send(method, program_name: 'fixture', suppress_progress: true)
    end

    it "surfaces GraphQL errors from #{method} and closes the transport" do
      allow(RestClient::Request).to receive(:execute).and_return(instance_double(RestClient::Response, body: { errors: [{ message: 'fixture query rejected' }] }.to_json))
      expect(PWN::Plugins::TransparentBrowser).to receive(:close).with(browser_obj: handle)
      expect do
        described_class.public_send(method, program_name: 'fixture', suppress_progress: true)
      end.to raise_error(RuntimeError, /GraphQL.*fixture query rejected/)
    end
  end

  it 'collects all scope pages instead of silently truncating the scope at the first page' do
    offsets = []
    allow(RestClient::Request).to receive(:execute) do |options|
      offset = JSON.parse(options[:payload]).fetch('variables').fetch('from')
      offsets << offset
      response = { data: { team: { structured_scopes_search: {
        nodes: [{ id: "scope-#{offset}" }], total_count: 2, pageInfo: { hasNextPage: offset.zero?, endCursor: offset.to_s }
      } } } }
      instance_double(RestClient::Response, body: response.to_json)
    end
    result = described_class.get_scope_details(program_name: 'fixture')
    expect(result[:scope_details][:data][:team][:structured_scopes_search][:nodes].map { |node| node[:id] }).to eq(%w[scope-0 scope-1])
    expect(offsets).to eq([0, 1])
  end

  it 'collects every hacktivity page up to the reported total count' do
    offsets = []
    allow(RestClient::Request).to receive(:execute) do |options|
      offset = JSON.parse(options[:payload]).fetch('variables').fetch('from')
      offsets << offset
      response = { data: { search: { nodes: [{ id: "report-#{offset}" }], total_count: 2 } } }
      instance_double(RestClient::Response, body: response.to_json)
    end
    result = described_class.get_hacktivity(program_name: 'fixture')
    expect(result[:hacktivity][:data][:search][:nodes].map { |node| node[:id] }).to eq(%w[report-0 report-1])
    expect(offsets).to eq([0, 1])
  end

  %i[get_scope_details get_hacktivity].each do |method|
    it "rejects repeated result IDs in #{method} pagination" do
      requests = 0
      allow(RestClient::Request).to receive(:execute) do
        requests += 1
        raise 'unexpected third request' if requests > 2

        search = { nodes: [{ id: 'same' }], total_count: 2, pageInfo: { hasNextPage: true } }
        data = method == :get_scope_details ? { team: { structured_scopes_search: search } } : { search: search }
        instance_double(RestClient::Response, body: { data: data }.to_json)
      end
      expect { described_class.public_send(method, program_name: 'fixture') }.to raise_error(RuntimeError, /pagination.*repeated/)
    end
  end

  it 'does not mask preflight validation with an unloaded RestClient rescue constant' do
    script = <<~'RUBY'
      require 'pwn'
      begin
        PWN::WWW::HackerOne.get_bounty_programs(min_payouts_enabled: 'invalid')
      rescue StandardError => e
        puts "#{e.class}: #{e.message}"
      end
    RUBY
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-I', File.expand_path('../../../../lib', __dir__), '-e', script)
    expect(status.success?).to be(true), stderr
    expect(stdout).to include('ERROR: min_payouts_enabled should be true or false')
  end

  %i[get_bounty_programs get_scope_details get_hacktivity].each do |method|
    it "does not invoke optional AI without configuration in #{method}" do
      stub_const('PWN::Env', {})
      expect(PWN::AI::Agent::HackerOne).not_to receive(:analyze)
      response = { data: {
        teams: { edges: [], pageInfo: { hasNextPage: false } },
        team: { structured_scopes_search: { nodes: [], total_count: 0, pageInfo: { hasNextPage: false } } },
        search: { nodes: [], total_count: 0 }
      } }
      allow(RestClient::Request).to receive(:execute).and_return(instance_double(RestClient::Response, body: response.to_json))
      described_class.public_send(method, program_name: 'fixture', suppress_progress: true)
    end
  end

  it 'closes the export transport and leaves caller browser options unchanged' do
    Dir.mktmpdir('pwn-h1-export-') do |dir|
      options = { proxy: 'http://fixture.invalid:8080' }.freeze
      programs = [{ name: 'fixture', burp_target_config: 'https://example.invalid/scope.json' }]
      allow(RestClient::Request).to receive(:execute).and_return(instance_double(RestClient::Response, body: '{"target":{"scope":{}}}'))
      expect(PWN::Plugins::TransparentBrowser).to receive(:close).with(browser_obj: handle)
      described_class.save_burp_target_config_file(programs_arr: programs, browser_opts: options, name: 'fixture', root_dir: dir)
      expect(JSON.parse(File.read(File.join(dir, 'burp_target_config_file-fixture.json')))).to eq('target' => { 'scope' => {} })
      expect(options).to eq(proxy: 'http://fixture.invalid:8080')
    end
  end

  it 'closes the export transport when a download fails' do
    Dir.mktmpdir('pwn-h1-export-') do |dir|
      programs = [{ name: 'fixture', burp_target_config: 'https://example.invalid/scope.json' }]
      allow(RestClient::Request).to receive(:execute).and_raise(IOError, 'fixture failure')
      expect(PWN::Plugins::TransparentBrowser).to receive(:close).with(browser_obj: handle)
      expect do
        described_class.save_burp_target_config_file(programs_arr: programs, name: 'fixture', root_dir: dir)
      end.to raise_error(IOError, 'fixture failure')
    end
  end

  it 'rejects a repeated bounty cursor instead of looping indefinitely' do
    requests = 0
    allow(RestClient::Request).to receive(:execute) do
      requests += 1
      raise 'unexpected third request' if requests > 2

      instance_double(RestClient::Response, body: { data: { teams: { edges: [], pageInfo: { hasNextPage: true, endCursor: 'same' } } } }.to_json)
    end
    expect { described_class.get_bounty_programs(suppress_progress: true) }.to raise_error(RuntimeError, /pagination.*cursor/)
    expect(requests).to eq(2)
  end
end
