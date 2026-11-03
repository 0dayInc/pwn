# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::Vault, 'native YubiKey selectors' do
  before do
    @device = double('offline native YubiKey')
    stub_const('PWN::Plugins::YubiKey', @device)
    allow(@device).to receive(:challenge_response) { |opts| OpenSSL::HMAC.digest('SHA1', 'fixture-slot', opts[:challenge]) }
  end

  it 'forwards caller-owned native controls unchanged and persists only public slot and serial selectors' do
    connection = double('native connection', exchange: ''.b)
    selector = { slot: 1, serial: '001234', device_path: '/fixture/native-device', connection: connection, timeout: 1.5 }.freeze
    expect(@device).to receive(:challenge_response).with(hash_including(selector)).twice
    envelope = described_class.seal_credentials(credentials: { token: 'fixture' }, yubikey: selector)
    expect(envelope.fetch('yubikey').keys).to contain_exactly('slot', 'serial', 'challenge')
    expect(envelope.fetch('yubikey')).to include('slot' => 1, 'serial' => '001234')
    expect(described_class.open_credentials(envelope: envelope, yubikey: selector)).to eq('token' => 'fixture')
  end

  it 'accepts an exact caller-owned smartcard reader without serial and never persists it' do
    selector = { slot: 2, reader: ' Fixture NFC reader ' }.freeze
    expect(@device).to receive(:challenge_response).with(hash_including(selector)).twice
    envelope = described_class.seal_credentials(credentials: {}, yubikey: selector)
    expect(envelope.fetch('yubikey').keys).to contain_exactly('slot', 'challenge')
    expect(described_class.open_credentials(envelope: envelope, yubikey: selector)).to eq({})
  end
end
