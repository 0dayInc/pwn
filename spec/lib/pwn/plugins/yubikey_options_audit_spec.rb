# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::YubiKey, 'HSM Auth facade options' do
  it 'documents typed HSM authorization options without device access' do
    expect(described_class::Transport).not_to receive(:open)
    expect { described_class.help }.to output(/management_password:.*auth_method:/m).to_stdout
  end

  it 'forwards an explicit management password through the real HSM Auth APDU codec' do
    connection = double('APDU transport', descriptor: { protocol: :apdu })
    expect(connection).to receive(:exchange).with(hash_including(data: ['00a4040008a000000527210701'].pack('H*'))).ordered.and_return(['79030508009000'].pack('H*'))
    payload = "\x7b\x10".b + 'old-fixture'.ljust(16, "\0") + "\x7b\x10".b + 'new-fixture'.ljust(16, "\0")
    expected = "\x00\x08\x00\x00".b + [payload.bytesize].pack('C') + payload
    expect(connection).to receive(:exchange).with(hash_including(data: expected)).ordered.and_return("\x90\x00".b)
    result = described_class.hsmauth(args: %w[access change-management-password], connection: connection,
                                     confirm: true, management_password: 'old-fixture', new_management_password: 'new-fixture')
    expect(result).to eq(status: :acknowledged, verification: :not_readable)
  end

  it 'retains the explicit credential authentication conflict guard at the facade' do
    connection = double('APDU transport', descriptor: { protocol: :apdu }, exchange: nil)
    expect do
      described_class.hsmauth(args: %w[credentials change-password fixture], connection: connection, confirm: true,
                              auth_method: :credential, management_key: 'x'.b * 16, new_credential_password: 'new-fixture')
    end.to raise_error(ArgumentError, /conflicts with explicit credential auth_method/)
    expect(connection).not_to have_received(:exchange)
  end
end
