# frozen_string_literal: true

require 'spec_helper'
require 'pwn/redaction'

RSpec.describe PWN::Redaction, 'hardware and MFA field redaction' do
  it 'masks complete management-secret containers in serialized text' do
    samples = [
      'scp_keys=["fixture-enc", "fixture-mac"] slot=2',
      'scp_keys: {enc: "fixture-enc", nested: ["fixture-mac", "fixture ] bracket"]} slot=2',
      "scp_keys=[\n\"fixture-enc\",\n[\"fixture-mac\"]\n] slot=2"
    ]
    samples.each do |text|
      clean = described_class.redact(value: text)
      expect(clean).not_to include('fixture-enc', 'fixture-mac', 'fixture ] bracket')
      expect(clean).to include('[REDACTED]', 'slot=2')
      expect(described_class.redact(value: clean)).to eq(clean)
    end
    expect(described_class.redact(value: 'scp_keys=["fixture-enc"')).to eq('scp_keys=[REDACTED]')
    expect(described_class.redact(value: 'oath_secret="fixture truncated secret')).to eq('oath_secret=[REDACTED]')
  end

  it 'does not let an existing mask exempt an adjacent ordinary secret from capture' do
    text = 'password=fixture-prefix[REDACTED]fixture-suffix'
    clean = described_class.capture(value: text, vault: false)
    expect(clean[:redacted]).not_to include('fixture-prefix', 'fixture-suffix')
    expect(clean[:refs]).not_to be_empty
  end

  it 'masks key-value text before ordinary token hashing or loot capture' do
    samples = [
      'pin=123456', 'PUK: 654321', 'new_pin="123 456"', "'management_key' => 'fixture key'",
      '--access-code=112233', 'oath_secret=fixture-oath', 'static_password=fixture-static',
      'scp_enc=fixture-enc', 'mfa_code=102938', '{"pin": "123456", "puk": 654321}'
    ]
    expect(PWN::Plugins::Vault).not_to receive(:store)
    expect(PWN::Plugins::Vault).not_to receive(:fetch)
    expect(PWN::Plugins::Vault).not_to receive(:expand)
    samples.each do |text|
      clean = described_class.redact(value: text)
      expect(clean).to include('[REDACTED]'), text
      expect(clean).not_to match(/123|654|112|102|fixture|\[REDACTED:[^\]]+/), text
      expect(described_class.redact(value: clean)).to eq(clean)
      expect(described_class.capture(value: text, entropy: true, yubikey: { slot: 2 })).to eq(redacted: clean, refs: [])
    end
    expect(described_class.redact(value: { api_key: 'fixture-api' })).to eq(api_key: described_class.token(kind: 'api_key', value: 'fixture-api'))
  end

  it 'uses a constant mask for structured PINs, PUKs, MFA codes and management secrets' do
    fields = %w[pin PIN new_pin current-pin admin_pin user_pin fido2_pin piv_pin openpgp_pin puk new_puk access_code management_key management_password oath_secret static_password scp scp_key scp_keys scp_enc scp_mac scp_dek scp03_enc_key mfa_code mfa_token otp totp hotp otp_code totp_secret recovery_code verification_code]
    fields.each do |field|
      first = described_class.redact(value: { field => '123456' })
      second = described_class.redact(value: { field => '654321' })
      expect(first).to eq(field => '[REDACTED]'), field
      expect(second).to eq(first), field
    end
    input = { nested: [{ pin: 1234, puk: nil, scp_keys: %w[fixture-one fixture-two] }], slot: 2, serial: '12345678', shipping: 'public' }
    expect(described_class.redact(value: input)).to eq(nested: [{ pin: '[REDACTED]', puk: nil, scp_keys: '[REDACTED]' }], slot: 2, serial: '12345678', shipping: 'public')
    expect(input[:nested].first[:pin]).to eq(1234)
  end
end
