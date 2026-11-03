# frozen_string_literal: true

require 'spec_helper'
require 'json_schemer'
require 'tmpdir'

RSpec.describe 'loot_query hardware selector' do
  before(:all) do
    PWN::AI::Agent::Registry.discover
  end

  it 'rejects an executable override at the actual Dispatch schema boundary' do
    allow(PWN::AI::Agent::Manifest).to receive(:load).and_return({})
    expect(PWN::Plugins::Vault).not_to receive(:store)
    expect(PWN::Plugins::Vault).not_to receive(:expand)
    raw = PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'loot_query', arguments: { op: 'store', secret: 'fixture-secret', yubikey: { ykman: '/fixture/arbitrary-executable' } } } })
    expect(JSON.parse(raw)).to include('success' => false, 'code' => 'SCHEMA_DENY')
  end

  it 'forwards selection through ingest while metadata-only query never opens the device' do
    Dir.mktmpdir('pwn-loot-query-yubikey-') do |root|
      allow(Dir).to receive(:home).and_return(root)
      allow(PWN::AI::Agent::Mission).to receive(:active_id).and_return(nil)
      device = double('offline YubiKey fixture')
      stub_const('PWN::Plugins::YubiKey', device)
      allow(device).to receive(:challenge_response) do |opts|
        expect(opts).to include(slot: 2, serial: '12345678', timeout: 2.5)
        OpenSSL::HMAC.digest('SHA1', 'synthetic-slot-secret', opts.fetch(:challenge))
      end
      handler = PWN::AI::Agent::Registry.lookup(name: 'loot_query').handler
      saved = handler.call('op' => 'ingest', 'text' => 'username=fixture-user password=fixture-password', 'engagement' => 'lab',
                           'yubikey' => { 'slot' => 2, 'serial' => '12345678', 'timeout' => 2.5 })
      expect(saved.first).to include(stored: true, engagement: 'lab', source: 'recon')
      expect(File).not_to exist(File.join(root, '.pwn-vault.key'))
      expect(device).not_to receive(:challenge_response)
      result = handler.call('op' => 'query', 'engagement' => 'lab')
      expect(result[:records].first).to include(has_secret: true, username: 'fixture-user')
      expect(result.to_s).not_to include('fixture-password')
    end
  end

  it 'advertises only a non-secret hardware selector without adding a tool' do
    count = PWN::AI::Agent::Registry.all.length
    load File.expand_path('../../../../../../lib/pwn/ai/agent/tools/loot_query.rb', __dir__)
    expect(PWN::AI::Agent::Registry.all.length).to eq(count)
    schema = PWN::AI::Agent::Registry.lookup(name: 'loot_query').schema.fetch(:parameters)
    selector = schema.fetch(:properties).fetch(:yubikey)
    expect(selector.fetch(:properties).keys).to contain_exactly(:slot, :serial, :timeout)
    validator = JSONSchemer.schema(JSON.parse(JSON.generate(schema)))
    expect(validator.valid?({ 'op' => 'store', 'yubikey' => { 'slot' => 2, 'serial' => '12345678', 'timeout' => 2.5 } })).to be(true)
    [{ 'ykman' => '/fixture/arbitrary-executable' }, { 'pin' => '123456' }, { 'slot' => 3 }, { 'serial' => 'invalid' }, { 'timeout' => 0 }, false].each do |invalid|
      expect(validator.valid?({ 'yubikey' => invalid })).to be(false), invalid.inspect
    end
  end
end
