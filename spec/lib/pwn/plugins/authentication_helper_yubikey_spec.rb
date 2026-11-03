# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::AuthenticationHelper do
  let(:yubikey) { { account: 'Example:tester@example.invalid', confirm: true, serial: '123456', device_path: '/fixture/native-device', timeout: 30 }.freeze }

  before do
    stub_const('PWN::Plugins::YubiKey', Module.new)
    allow(PWN::Plugins::YubiKey).to receive(:oath_code).and_return('012345')
    allow(TTY::Prompt).to receive(:new).and_raise('unexpected interactive prompt')
  end

  it 'returns the YubiKey OATH digits without removing a leading zero or prompting' do
    expect(PWN::Plugins::YubiKey).to receive(:oath_code).with(yubikey).and_return('012345')
    expect(described_class.mfa(yubikey: yubikey)).to eq('012345')
  end

  [false, true, 'Example', [], {}, { account: nil }, { account: 123 }, { account: '' }, { account: '  ' }, { account: "Example\nOther" }].each do |invalid|
    it "rejects invalid YubiKey options #{invalid.inspect} without a device call or prompt" do
      expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
      expect { described_class.mfa(yubikey: invalid) }.to raise_error(ArgumentError, /yubikey|account/)
    end
  end

  it 'preserves the exact account name and caller options' do
    exact = { account: ' Example:tester@example.invalid ', confirm: true }.freeze
    expect(PWN::Plugins::YubiKey).to receive(:oath_code).with(exact).and_return('00123456')
    expect(described_class.mfa(yubikey: exact)).to eq('00123456')
  end

  it 'propagates a YubiKey failure without falling back to an interactive prompt' do
    allow(PWN::Plugins::YubiKey).to receive(:oath_code).and_raise(IOError, 'device unavailable')
    expect { described_class.mfa(yubikey: yubikey) }.to raise_error(IOError, 'device unavailable')
  end

  it 'rejects an OTP slot instead of treating it as an OATH credential' do
    expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
    expect { described_class.mfa(yubikey: yubikey.merge(slot: 2)) }.to raise_error(ArgumentError, /slot.*OATH/)
  end

  it 'propagates device cancellation instead of returning a value for a form' do
    allow(PWN::Plugins::YubiKey).to receive(:oath_code).and_raise(Interrupt)
    expect { described_class.mfa(yubikey: yubikey) }.to raise_error(Interrupt)
  end

  [nil, false, 'true', 1].each do |confirm|
    it "rejects confirm #{confirm.inspect} before a device call or prompt" do
      expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
      expect { described_class.mfa(yubikey: yubikey.merge(confirm: confirm)) }.to raise_error(ArgumentError, /confirm: true.*HOTP.*authenticat/i)
    end
  end

  it 'requires explicit consent during pre-login validation without modifying options' do
    options = { yubikey: yubikey.except(:confirm).freeze }.freeze
    expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
    expect { described_class.validate_mfa_options(options) }.to raise_error(ArgumentError, /confirm: true/)
    expect(options[:yubikey]).not_to have_key(:confirm)
  end

  it 'does not accept string-keyed consent as the literal confirm option' do
    expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
    expect { described_class.mfa(yubikey: yubikey.except(:confirm).merge('confirm' => true)) }.to raise_error(ArgumentError, /confirm: true/)
  end

  it 'keeps malformed-account and OTP-slot errors ahead of missing consent' do
    expect { described_class.validate_mfa_options(yubikey: { account: '' }) }.to raise_error(ArgumentError, /account must/)
    expect { described_class.validate_mfa_options(yubikey: { slot: 2 }) }.to raise_error(ArgumentError, /slot.*OATH/)
  end

  [{ mfa: '654321' }, { mfa_token: '654321' }].each do |conflict|
    it "keeps the #{conflict.keys.first} conflict ahead of missing consent" do
      expect { described_class.validate_mfa_options(conflict.merge(yubikey: yubikey.except(:confirm))) }.to raise_error(ArgumentError, /combined.*mfa.*mfa_token/)
    end
  end

  it 'documents exact OATH selection, optional device controls, and fail-closed behavior' do
    expect { described_class.help }.to output(/yubikey:.*exact.*account.*serial.*reader.*device_path.*connection.*timeout.*password.*secret_provider.*no OTP slot.*validate_mfa_options/m).to_stdout
    expect { described_class.help }.to output(/Example yubikey: \{ account: 'EXACT_OATH_NAME', confirm: true.*HOTP.*authenticat/m).to_stdout
    expect { described_class.help }.not_to output(/ykman/).to_stdout
  end

  it 'preserves the manual prompt when YubiKey is not selected' do
    prompt = instance_double(TTY::Prompt)
    allow(TTY::Prompt).to receive(:new).and_return(prompt)
    expect(prompt).to receive(:ask).with('Test MFA: ').and_return(" 012345\n")
    expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
    expect(described_class.mfa(prompt: 'Test MFA')).to eq('012345')
  end
end
