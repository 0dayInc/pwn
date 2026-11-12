# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::YubiKey, 'borrowed connection selectors' do
  %i[serial reader device_path].each do |selector|
    [nil, 'other'].each do |observed|
      it "rejects #{selector} #{observed.nil? ? 'missing from' : 'mismatching'} the borrowed descriptor before APDUs" do
        connection = double('borrowed transport', descriptor: { protocol: :apdu, selector => observed })
        allow(connection).to receive(:exchange).and_return("\x90\x00".b)
        expect(connection).not_to receive(:close)
        expect(described_class::Transport).not_to receive(:open)
        options = { connection: connection, selector => '123', confirm: true, ins: 0xa4 }
        expect { described_class.apdu(options) }.to raise_error(ArgumentError, /selector/)
        expect(connection).not_to have_received(:exchange)
      end
    end
  end

  it 'retains an exactly matching borrowed connection and does not close it' do
    connection = double('borrowed transport', descriptor: { protocol: :apdu, serial: '00123' })
    expect(connection).to receive(:exchange).with(hash_including(data: "\x00\xa4\x00\x00\x00".b)).and_return("\x90\x00".b)
    expect(connection).not_to receive(:close)
    expect(described_class.apdu(connection: connection, serial: '00123', confirm: true, ins: 0xa4)).to eq(''.b)
  end
end
