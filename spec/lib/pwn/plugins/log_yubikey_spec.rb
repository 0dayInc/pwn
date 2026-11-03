# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe PWN::Plugins::Log, 'hardware credential logging' do
  it 'masks sensitive trace keys before the general credential digest path' do
    fields = %i[pin puk access_code management_key oath_secret static_password scp_keys mfa_code]
    fields.each do |key|
      expect(described_class.send(:inspect_debug, key: key, value: '123456')).to eq('[REDACTED]')
      expect(described_class.send(:inspect_debug, key: key, value: '654321')).to eq('[REDACTED]')
    end
    expect(described_class.send(:inspect_debug, key: :api_key, value: 'fixture-api')).to eq(PWN::Redaction.token(kind: 'credential', value: 'fixture-api'))
  end

  it 'redacts nested structured debug values without consulting the credential store' do
    expect(PWN::Plugins::Vault).not_to receive(:redact)
    expect(PWN::Plugins::Vault).not_to receive(:expand)
    expect(PWN::Plugins::Vault).not_to receive(:fetch)
    input = { selector: { slot: 2, serial: '12345678' }, nested: [{ pin: '123456', scp_keys: %w[fixture-enc fixture-mac] }] }
    text = described_class.send(:inspect_debug, value: input)
    expect(text).to include('slot: 2', 'serial: "12345678"', '[REDACTED]')
    expect(text).not_to include('pin: "123456"', 'fixture-enc', 'fixture-mac', '[REDACTED:credential:')
    expect(input[:nested].first[:pin]).to eq('123456')
  end

  it 'writes only constant masks for PIN and management fields to log, debug, mirror and stderr sinks' do
    Dir.mktmpdir('pwn-log-yubikey-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      fixture = 'pin=123456 management_key=fixture-management mfa_code=654321'
      described_class.append(level: :info, msg: { pin: '123456', management_key: 'fixture-management' })
      path = File.join(dir, 'debug.log')
      described_class.start_debug(path: path)
      described_class.progress(msg: fixture)
      described_class.mirror_tui!(msg: fixture)
      described_class.capture_stderr!(text: "#{fixture}\n")
      described_class.stop_debug
      [path, File.join(dir, '.pwn', 'logs', 'pwn.log')].each do |file|
        body = File.read(file)
        expect(body).to include('[REDACTED]')
        expect(body).not_to include('123456', '654321', 'fixture-management', '[REDACTED:')
      end
    ensure
      described_class.stop_debug
    end
  end
end
