# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::YubiKey, 'primary failure preservation' do
  it 'preserves an owned facade operation failure when closing the handle also fails' do
    connection = double('owned transport', descriptor: { protocol: :apdu })
    allow(described_class::Transport).to receive(:open).and_return(connection)
    allow(connection).to receive(:exchange).and_raise(described_class::TimeoutError, 'fixture primary timeout')
    allow(connection).to receive(:close).and_raise(IOError, 'fixture secondary close')
    expect { described_class.apdu(ins: 0xa4, confirm: true, reader: 'fixture-reader') }.to raise_error(described_class::TimeoutError, 'fixture primary timeout')
    expect(connection).to have_received(:close).once
  end

  it 'preserves an in-flight native operation error while retiring its failed connection' do
    io = double('native IO')
    allow(io).to receive(:transmit).and_raise(described_class::CommandError, 'fixture primary transmit')
    allow(io).to receive(:close).and_raise(IOError, 'fixture secondary close')
    connection = described_class::Transport::Connection.new(descriptor: { protocol: :apdu }, io: io)
    expect { connection.exchange(protocol: :apdu, data: "\x00\xa4\x00\x00".b) }.to raise_error(described_class::CommandError, 'fixture primary transmit')
    expect { connection.exchange(protocol: :apdu, data: "\x00\xa4\x00\x00".b) }.to raise_error(described_class::Error, /closed/)
    expect(io).to have_received(:close).once
  end

  it 'preserves HID acquisition errors when native release also fails' do
    require 'ffi'
    library = double('HID library', hid_open_path: FFI::Pointer::NULL)
    native = double('HID backend', acquire: nil, library: library)
    allow(native).to receive(:release).and_raise(IOError, 'fixture release failure')
    expect { described_class::Transport::HIDIO.new(native, '/fixture/hid') }.to raise_error(described_class::CommandError, /Cannot open/)
  end

  it 'preserves PCSC acquisition status when context release also fails' do
    require 'ffi'
    library = double('PCSC library', SCardConnect: 0x123, SCardReleaseContext: 0x456)
    allow(library).to receive(:SCardEstablishContext) do |_, _, _, pointer|
      pointer.write_long(1)
      0
    end
    native = double('PCSC backend', library: library, handle_type: :long, dword: :ulong, platform: :linux)
    expect { described_class::Transport::PCSCIO.new(native, 'fixture-reader') }.to raise_error(described_class::CommandError, /connect.*00000123/)
  end

  it 'preserves PCSC discovery status when context release also fails' do
    require 'ffi'
    library = double('PCSC library', SCardListReaders: 0x123, SCardReleaseContext: 0x456)
    allow(library).to receive(:SCardEstablishContext) do |_, _, _, pointer|
      pointer.write_long(1)
      0
    end
    native = double('PCSC backend', library: library, handle_type: :long, dword: :ulong)
    expect { described_class::Transport::PCSCInventory.new(native).devices }.to raise_error(described_class::CommandError, /00000123/)
  end

  it 'preserves a secure-channel handshake failure during invalidation' do
    connection = double('plain APDU', descriptor: { protocol: :apdu })
    allow(connection).to receive(:exchange).and_raise(described_class::TimeoutError, 'fixture primary handshake')
    allow(connection).to receive(:close).and_raise(IOError, 'fixture secondary close')
    expect do
      described_class::SecurityDomain.secure_connection(connection: connection, scp: :scp03, kvn: 1,
                                                        key_enc: 'a'.b * 16, key_mac: 'b'.b * 16, confirm: true)
    end.to raise_error(described_class::TimeoutError, 'fixture primary handshake')
    expect(connection).to have_received(:close).once
  end
end
