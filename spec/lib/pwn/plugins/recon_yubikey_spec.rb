# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::Recon, 'hardware loot capture' do
  it 'keeps hardware failures visible without creating software loot or a master key' do
    Dir.mktmpdir('pwn-recon-yubikey-failure-') do |root|
      allow(Dir).to receive(:home).and_return(root)
      device = double('offline unavailable YubiKey')
      stub_const('PWN::Plugins::YubiKey', device)
      allow(device).to receive(:challenge_response).and_raise(IOError, 'fixture device unavailable')
      assets = [{ address: 'app.example.test', observations: [{ banner: 'password=fixture-password' }] }]
      expect { described_class.harvest_loot(assets: assets, engagement_id: 'lab', yubikey: { slot: 2 }) }.to raise_error(IOError, 'fixture device unavailable')
      expect(File).not_to exist(File.join(root, '.pwn-vault.key'))
      expect(PWN::Plugins::Vault.query(engagement: 'lab')).to be_empty
    end
  end

  it 'forwards the explicit selector through run and harvest into real hardware-encrypted loot' do
    Dir.mktmpdir('pwn-recon-yubikey-') do |root|
      allow(Dir).to receive(:home).and_return(root)
      allow(PWN::AI::Agent::Mission).to receive(:active_id).and_return(nil)
      device = double('offline YubiKey fixture')
      stub_const('PWN::Plugins::YubiKey', device)
      selector = { slot: 2, serial: '12345678', timeout: 4, device_path: '/fixture/native-device' }
      allow(device).to receive(:challenge_response) do |opts|
        expect(opts).to include(selector)
        OpenSSL::HMAC.digest('SHA1', 'synthetic-slot-secret', opts.fetch(:challenge))
      end
      socket = double('offline banner', readpartial: "username=fixture-user\npassword=fixture-password\n", remote_address: double(ip_address: '192.0.2.10'))
      allow(Socket).to receive(:tcp).and_yield(socket)
      result = described_class.run(target: 'app.example.test', modules: ['banner'], ports: [22], engagement_id: 'lab', root: root, yubikey: selector)
      expect(File).not_to exist(File.join(root, '.pwn-vault.key'))
      expect(device).to have_received(:challenge_response).once
      rows = JSON.parse(File.read(File.join(root, '.pwn', 'engagements', 'lab', 'loot.json'))).fetch('records')
      expect(rows.first.dig('secret', 'kdf')).to eq('yubikey-hmac-sha1-hkdf-sha256')
      expect(rows.first.dig('secret', 'yubikey')).to include('slot' => 2, 'serial' => '12345678')
      expect(result[:loot].first).to include(engagement: 'lab', source: 'recon', where: 'banner:22', host: '192.0.2.10')
      expect(PWN::Plugins::Vault.fetch(label: result[:loot].first[:label], engagement: 'lab', yubikey: selector)).to eq('fixture-password')
    end
  end
end
