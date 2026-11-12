# frozen_string_literal: true

require 'spec_helper'
require 'base64'

RSpec.describe PWN::AWS::IAM, 'key decoding regressions' do
  %i[secret_access_key sts_session_token].each do |type|
    it "preserves case-sensitive Base64 bytes for #{type}" do
      bytes = "fixture\x00payload\xff".b
      encoded = Base64.strict_encode64(bytes)
      result = described_class.decode_key(key: encoded, key_type: type)
      expect(result[:decoded_key]).to eq(bytes)
      expect(result[:key_type]).to eq(type)
      expect(encoded).to eq(Base64.strict_encode64(bytes))
    end
  end

  it 'keeps access-key Base32 decoding case-insensitive' do
    suffix = "#{[0x800000000080].pack('Q>').byteslice(2, 6)}seed"
    key = "AKIA#{Base32.encode(suffix)}"
    expect(described_class.decode_key(key: key.downcase)).to eq(described_class.decode_key(key: key))
  end
end
