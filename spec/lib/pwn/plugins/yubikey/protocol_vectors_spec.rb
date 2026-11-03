# frozen_string_literal: true

require 'spec_helper'
require 'json'

RSpec.describe PWN::Plugins::YubiKey::Protocol, 'independent APDU frame vectors' do
  vectors = JSON.parse(File.read(File.expand_path('../../../../fixtures/yubikey/apdu_frames.json', __dir__))).fetch('vectors')

  vectors.each do |vector|
    it "matches the reference formatter for #{vector.fetch('name')}" do
      options = vector.fetch('options').transform_keys(&:to_sym)
      options[:data] = [options.delete(:data_hex)].pack('H*')
      connection = double('offline smartcard')
      expect(connection).to receive(:exchange).with(hash_including(protocol: :apdu, data: [vector.fetch('expected_hex')].pack('H*'))).once.and_return("\x90\x00".b)
      expect(described_class.apdu(options.merge(connection: connection))).to eq(''.b)
    end
  end
end
