# frozen_string_literal: true

require 'spec_helper'
require 'pwn/plugins/yubikey/security_domain'
require_relative 'security_domain/support'

RSpec.describe PWN::Plugins::YubiKey::Protocol, 'secure-channel integration' do
  it 'protects one complete command before any transport-level fragmentation' do
    card = Scp03Card.new
    card.handler = ->(_header, _body) { ['accepted'.b, "\x90\x00".b] }
    key = (0...16).to_a.pack('C*')
    channel = PWN::Plugins::YubiKey::SecurityDomain.secure_connection(connection: card, scp: :scp03, kvn: 1, key_enc: key, key_mac: key, key_dek: key, confirm: true)
    before = card.commands.length
    payload = 'x'.b * 300
    expect(described_class.apdu(connection: channel, ins: 0xda, data: payload)).to eq('accepted'.b)
    expect(card.received).to eq(payload)
    expect(card.commands.length - before).to eq(1)
    expect(card.commands.last.getbyte(4)).to eq(0)
  ensure
    channel&.close
  end

  it 'rejects an explicit short-framing override for a secure connection before I/O' do
    connection = double('secure connection', descriptor: { secure_channel: :scp03, extended_apdu: true }, exchange: nil)
    expect(connection).not_to receive(:exchange)
    expect { described_class.apdu(connection: connection, ins: 0xda, extended: false) }.to raise_error(ArgumentError, /extended/)
  end
end
