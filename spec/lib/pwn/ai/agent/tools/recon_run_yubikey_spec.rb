# frozen_string_literal: true

require 'spec_helper'
require 'json_schemer'
require 'tmpdir'

RSpec.describe 'recon_run hardware selector' do
  before do
    PWN::AI::Agent::Registry.discover
  end

  it 'advertises the nonsecret selector and rejects executable overrides before recon runs' do
    entry = PWN::AI::Agent::Registry.lookup(name: 'recon_run')
    selector = entry.schema.fetch(:parameters).fetch(:properties).fetch(:yubikey)
    expect(selector.fetch(:properties).keys).to contain_exactly(:slot, :serial, :timeout)
    validator = JSONSchemer.schema(JSON.parse(JSON.generate(entry.schema.fetch(:parameters))))
    expect(validator.valid?({ 'target' => 'app.example.test', 'modules' => ['banner'], 'yubikey' => { 'slot' => 2, 'serial' => '12345678' } })).to be(true)
    allow(PWN::AI::Agent::Manifest).to receive(:load).and_return({})
    expect(PWN::Plugins::Recon).not_to receive(:run)
    raw = PWN::AI::Agent::Dispatch.call(tool_call: { function: { name: 'recon_run', arguments: { target: 'app.example.test', modules: ['banner'], yubikey: { ykman: '/fixture/untrusted-executable' } } } })
    expect(JSON.parse(raw)).to include('success' => false, 'code' => 'SCHEMA_DENY')
  end

  it 'carries JSON selector keys through the real recon handler into hardware-protected loot' do
    Dir.mktmpdir('pwn-recon-tool-yubikey-') do |root|
      allow(Dir).to receive(:home).and_return(root)
      allow(PWN::AI::Agent::Mission).to receive(:active_id).and_return(nil)
      allow(PWN::Plugins::YubiKey).to receive(:challenge_response) do |opts|
        expect(opts).to include(slot: 2, serial: '12345678', timeout: 4)
        OpenSSL::HMAC.digest('SHA1', 'synthetic-slot-secret', opts.fetch(:challenge))
      end
      socket = double('offline banner', readpartial: "username=fixture-user\npassword=fixture-password\n", remote_address: double(ip_address: '192.0.2.10'))
      allow(Socket).to receive(:tcp).and_yield(socket)
      entry = PWN::AI::Agent::Registry.lookup(name: 'recon_run')
      selector = { 'slot' => 2, 'serial' => '12345678', 'timeout' => 4 }
      result = entry.handler.call('target' => 'app.example.test', 'modules' => ['banner'], 'ports' => [22], 'root' => root,
                                  'ingest' => false, 'engagement_id' => 'lab', 'yubikey' => selector)
      label = result.fetch(:loot).first.fetch(:label)
      expect(PWN::Plugins::Vault.fetch(label: label, engagement: 'lab', yubikey: selector)).to eq('fixture-password')
      expect(File).not_to exist(File.join(root, '.pwn-vault.key'))
    end
  end
end
