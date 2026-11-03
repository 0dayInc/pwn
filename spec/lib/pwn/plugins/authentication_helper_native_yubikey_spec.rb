# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::AuthenticationHelper, 'native YubiKey validation' do
  before do
    stub_const('PWN::Plugins::YubiKey', double('offline native device'))
    expect(TTY::Prompt).not_to receive(:new)
  end

  [{ ykman: '/fixture/unsupported' }, { timeout: false }, { timeout: 0 }, { timeout: Float::INFINITY },
   { reader: false }, { reader: '' }, { reader: "bad\nreader" }, { device_path: false }, { device_path: '' },
   { device_path: "bad\0path" }, { serial: 123 }, { serial: false }, { serial: ' 123' },
   { serial: '123', reader: 'Fixture reader' }, { reader: 'Fixture reader', device_path: '/fixture/native-device' }, { connection: false }, { connection: Object.new },
   { password: false }, { password: '' }, { secret_provider: false }, { secret_provider: Object.new }].each do |invalid|
    it "rejects #{invalid.keys.join('/')} controls before login, prompts or a device operation" do
      selector = { account: 'Fixture:account', confirm: true }.merge(invalid)
      expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
      expect { described_class.validate_mfa_options(yubikey: selector) }.to raise_error(ArgumentError, /yubikey/i)
      expect { described_class.mfa(yubikey: selector) }.to raise_error(ArgumentError, /yubikey/i)
    end
  end

  it 'forwards an exact native connection and in-memory password without inspecting or persisting them' do
    connection = double('native connection', exchange: ''.b)
    selector = { account: ' Fixture:account ', confirm: true, reader: ' Fixture reader ', connection: connection, password: 'fixture-only-password' }.freeze
    expect(PWN::Plugins::YubiKey).to receive(:oath_code).with(selector).and_return('000123')
    expect(described_class.mfa(yubikey: selector)).to eq('000123')
  end

  it 'does not invoke a secret provider during source selection and passes it unchanged to the native helper' do
    provider = double('operator secret provider', call: 'fixture-only-password')
    expect(provider).not_to receive(:call)
    selector = { account: 'Fixture:account', confirm: true, serial: '001234', device_path: '/fixture/native-device', secret_provider: provider }.freeze
    options = { yubikey: selector }.freeze
    expect(described_class.validate_mfa_options(options)).to equal(options)
    expect(PWN::Plugins::YubiKey).to receive(:oath_code).with(selector).and_return('00123456')
    expect(described_class.mfa(options)).to eq('00123456')
  end
end
