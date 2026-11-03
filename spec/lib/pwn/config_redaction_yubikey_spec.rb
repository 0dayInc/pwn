# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Config, 'YubiKey configuration redaction' do
  it 'redacts string-keyed hardware settings inside arrays without hiding public selectors' do
    config = { devices: [{ 'PIN' => '1', 'management-key' => 'synthetic-key', 'oath-secret' => 'synthetic-oath', 'serial' => '12345678', 'slot' => 2 }] }
    result = described_class.redact_sensitive_artifacts(config: config)
    masked = result[:devices].first
    expect(masked.values_at('PIN', 'management-key', 'oath-secret').uniq).to eq(['>>> REDACTED >>> USE `pwn-vault` FOR ADMINISTRATION <<< REDACTED <<<'])
    expect(masked).to include('serial' => '12345678', 'slot' => 2)
    expect(config.dig(:devices, 0, 'PIN')).to eq('1')
  end

  it 'uses the same constant mask for short PINs and hardware secrets while retaining public selectors' do
    fields = %i[pin new_pin admin_pin puk new_puk management_key new_management_key management_password access_code new_access_code oath_secret oath_password unlock_code unlock_password lock_code new_lock_code reset_code scp scp_key scp_keys scp03_key scp11_key static_password hmac_secret]
    values = fields.to_h { |field| [field, '123456'] }
    values[:pin] = '1'
    values[:puk] = '87654321'
    config = { plugins: { yubikey: values.merge(serial: '12345678', slot: 2, reader: 'fixture-reader') } }
    before = Marshal.dump(config)
    redacted = described_class.redact_sensitive_artifacts(config: config).dig(:plugins, :yubikey)
    mask = described_class.redact_sensitive_artifacts(config: { password: 'different-value' })[:password]
    fields.each { |field| expect(redacted[field]).to eq(mask), "#{field} must use the constant mask" }
    expect(redacted).to include(serial: '12345678', slot: 2, reader: 'fixture-reader')
    expect(Marshal.dump(config)).to eq(before)
  end
end
