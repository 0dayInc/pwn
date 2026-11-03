# frozen_string_literal: true

require 'spec_helper'
require 'ffi'
require 'pwn/plugins/yubikey/transport' if File.file?(File.join(__dir__, '../../../../../lib/pwn/plugins/yubikey/transport.rb'))

RSpec.shared_context 'native YubiKey wire fixtures' do
  let(:transport) { PWN::Plugins::YubiKey::Transport }

  def packet(hex)
    [hex].pack('H*').ljust(64, "\0")
  end

  def fake_io(packets: [], features: [])
    Class.new do
      attr_reader :writes, :feature_writes, :closed

      def initialize(packets, features)
        @packets = packets
        @features = features
        @writes = []
        @feature_writes = []
        @closed = 0
      end

      def read_packet(_milliseconds)
        @packets.shift || ''.b
      end

      def write_packet(bytes)
        @writes << bytes
      end

      def read_feature
        @features.shift || ("\0" * 8)
      end

      def write_feature(bytes)
        @feature_writes << bytes
      end

      def close
        @closed += 1
      end
    end.new(packets, features)
  end

  def fake_hid_library
    lib = Module.new
    allow(lib).to receive(:ffi_lib)
    allow(lib).to receive(:attach_function)
    lib
  end
end

RSpec.describe 'PWN::Plugins::YubiKey::Transport native boundary' do
  include_context 'native YubiKey wire fixtures'

  it 'negotiates CTAPHID INIT with a nonce and reassembles an independent continuation fixture' do
    allow(SecureRandom).to receive(:random_bytes).with(8).and_return('abcdefgh')
    # FIDO CTAPHID: broadcast INIT, 17-byte reply, CID 01020304, v2, fw 5.7.1, CBOR.
    io = fake_io(packets: [packet('ffffffff8600116162636465666768010203040205070104'),
                           packet("0102030490003c#{'a5' * 57}"),
                           packet('0102030400a5a5a5')])
    conn = transport::Connection.new(descriptor: { protocol: :ctap }, io: io, timeout: 1)
    expect(conn.exchange(protocol: :ctap, command: 0x10, data: "\x01".b)).to eq("\xa5".b * 60)
    expect(io.writes).to eq([packet('ffffffff8600086162636465666768'), packet('0102030490000101')])
    expect(conn.descriptor).to include(protocol: :ctap, version: [5, 7, 1], capabilities: 4)
    conn.close
    conn.close
    expect(io.closed).to eq(1)
  end

  it 'frames OTP serial requests with a fixed CRC fixture and strips the checked response CRC' do
    status = ['0005070109000000'].pack('H*')
    io = fake_io(features: [status, status, status, ['0001020329a70040'].pack('H*'), ['0000000000000040'].pack('H*')])
    conn = transport::Connection.new(descriptor: { protocol: :otp }, io: io, timeout: 1)
    expect(conn.exchange(protocol: :otp, command: 0x10, data: ''.b, response_length: 4)).to eq(['00010203'].pack('H*'))
    # CRC16 of 64 zero bytes is 5b6b (uncomplemented). Only first/last chunks are sent.
    expect(io.feature_writes).to eq(%w[0000000000000080 00106b5b00000089 00000000000000ff].map { |h| [h].pack('H*') })
    conn.close
    expect(io.closed).to eq(1)
  end

  it 'enumerates HID interfaces via FFI, preserves wide serial text, and frees all native resources' do
    native = transport::NativeLibrary.new(:hid, library: fake_hid_library, platform: :linux)
    lib = native.library
    text = FFI::MemoryPointer.new(:uint32, 7)
    text.write_array_of_uint32(' 0007 '.codepoints + [0])
    path = FFI::MemoryPointer.from_string('/fake/hid')
    # Independent C hid_device_info layout (HIDAPI 0.14 ABI prefix).
    struct = Class.new(FFI::Struct) do
      layout :path, :pointer, :vendor_id, :ushort, :product_id, :ushort,
             :serial_number, :pointer, :release_number, :ushort, :manufacturer_string, :pointer,
             :product_string, :pointer, :usage_page, :ushort, :usage, :ushort,
             :interface_number, :int, :next, :pointer
    end.new
    struct[:path] = path
    struct[:vendor_id] = 0x1050
    struct[:product_id] = 0x0407
    struct[:serial_number] = text
    struct[:usage_page] = 0xf1d0
    struct[:usage] = 1
    struct[:next] = FFI::Pointer::NULL
    expect(lib).to receive(:hid_init).ordered.and_return(0)
    expect(lib).to receive(:hid_enumerate).with(0x1050, 0).ordered.and_return(struct.pointer)
    expect(lib).to receive(:hid_free_enumeration).with(struct.pointer).ordered
    expect(lib).to receive(:hid_exit).ordered.and_return(0)
    expect(native.devices).to include(include(protocol: :ctap, device_path: '/fake/hid', serial: ' 0007 '))
  end

  it 'uses HIDAPI report-id prefixes and exact transfer lengths at the C boundary' do
    native = transport::NativeLibrary.new(:hid, library: fake_hid_library, platform: :linux)
    lib = native.library
    ptr = FFI::MemoryPointer.new(:char)
    expect(lib).to receive(:hid_init).and_return(0)
    expect(lib).to receive(:hid_open_path).with('/fake/hid').and_return(ptr)
    expect(lib).to receive(:hid_write) do |handle, buffer, length|
      expect(handle).to eq(ptr)
      expect(length).to eq(65)
      expect(buffer.read_bytes(length)).to eq("\0#{packet('01020304810000')}")
      65
    end
    expect(lib).to receive(:hid_get_feature_report) do |handle, buffer, length|
      expect(handle).to eq(ptr)
      expect(length).to eq(9)
      expect(buffer.get_uint8(0)).to eq(0)
      buffer.put_bytes(0, ['000005070109000000'].pack('H*'))
      9
    end
    expect(lib).to receive(:hid_close).with(ptr).ordered
    expect(lib).to receive(:hid_exit).ordered.and_return(0)
    io = native.open({ device_path: '/fake/hid', protocol: :ctap })
    io.write_packet(packet('01020304810000'))
    expect(io.read_feature).to eq(['0005070109000000'].pack('H*'))
    io.close
    io.close
  end

  it 'performs PC/SC exclusive connect and a raw APDU exchange through the C ABI' do
    lib = fake_hid_library
    pci = FFI::MemoryPointer.new(:ulong, 2)
    pci.write_array_of_ulong([2, FFI.type_size(:ulong) * 2])
    allow(lib).to receive(:ffi_libraries).and_return([double(find_symbol: pci)])
    native = transport::NativeLibrary.new(:pcsc, library: lib, platform: :linux)
    expect(lib).to receive(:SCardEstablishContext).with(2, nil, nil, anything) do |_, _, _, ptr|
      ptr.write_long(123)
      0
    end
    expect(lib).to receive(:SCardConnect) do |context, reader, share, preferred, card, protocol| # rubocop:disable Metrics/ParameterLists -- Mirrors the native C signature.
      expect([context, reader.read_string, share, preferred]).to eq([123, 'Yubico YubiKey synthetic', 1, 3])
      card.write_long(456)
      protocol.write_ulong(2)
      0
    end
    expect(lib).to receive(:SCardGetAttrib) do |card, attribute, atr, length|
      expect([card, attribute]).to eq([456, 0x00090303])
      atr.put_bytes(0, ['3bf81300008131fe15597562696b657934d4'].pack('H*'))
      length.write_ulong(17)
      0
    end
    expect(lib).to receive(:SCardTransmit) do |card, send_pci, data, size, receive_pci, output, length| # rubocop:disable Metrics/ParameterLists -- Mirrors the native C signature.
      expect([card, send_pci, data.read_bytes(size), receive_pci]).to eq([456, pci, ['00a4040000'].pack('H*'), nil])
      output.put_bytes(0, ['0102039000'].pack('H*'))
      length.write_ulong(5)
      0
    end
    expect(lib).to receive(:SCardDisconnect).with(456, 0).ordered.and_return(0)
    expect(lib).to receive(:SCardReleaseContext).with(123).ordered.and_return(0)
    io = native.open({ reader: 'Yubico YubiKey synthetic', protocol: :apdu })
    conn = transport::Connection.new(descriptor: { protocol: :apdu }, io: io, timeout: 1)
    expect(conn.descriptor[:transport]).to eq(:usb)
    expect(conn.exchange(protocol: :apdu, data: ['00a4040000'].pack('H*'))).to eq(['0102039000'].pack('H*'))
    conn.close
    conn.close
  end

  it 'uses platform-specific PC/SC DWORD and handle widths without establishing contexts' do
    { linux: %i[ulong long long], macos: %i[uint32 int32 int32], windows: %i[uint32 uintptr_t int32] }.each do |platform, (dword, handle, result)|
      lib = fake_hid_library
      allow(lib).to receive(:ffi_convention)
      allow(lib).to receive(:ffi_libraries).and_return([double(find_symbol: FFI::Pointer.new(1))])
      expect(lib).to receive(:attach_function).with(:SCardEstablishContext, [dword, :pointer, :pointer, :pointer], result, blocking: true)
      expect(lib).to receive(:attach_function).with(:SCardTransmit, [handle, :pointer, :pointer, dword, :pointer, :pointer, :pointer], result, blocking: true)
      expect(lib).not_to receive(:SCardEstablishContext)
      transport::NativeLibrary.new(:pcsc, library: lib, platform: platform)
    end
  end

  it 'bounds a blocked C call without freeing its handle early and closes it after the call returns' do
    entered = Queue.new
    release = Queue.new
    io = fake_io
    allow(io).to receive(:transmit) do |_data|
      entered << true
      release.pop
      "\x90\x00".b
    end
    conn = transport::Connection.new(descriptor: { protocol: :apdu }, io: io, timeout: 0.04)
    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    timer = Thread.new do
      entered.pop
      sleep(0.2)
      release << true
    end
    expect { conn.exchange(protocol: :apdu, data: "\x00\xa4\x04\x00".b) }.to raise_error(PWN::Plugins::YubiKey::TimeoutError)
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - start).to be < 0.18
    expect(io.closed).to eq(0)
    expect { conn.exchange(protocol: :apdu, data: "\x00\xa4\x04\x00".b) }.to raise_error(PWN::Plugins::YubiKey::Error, /closed/)
    timer.join
    conn.close
    expect(io.closed).to eq(1)
  ensure
    release << true if release
    timer&.join(1)
    conn&.close
  end

  it 'cancels CTAPHID on touch-wait interruption and closes exactly once' do
    allow(SecureRandom).to receive(:random_bytes).and_return('abcdefgh')
    io = fake_io(packets: [packet('ffffffff8600116162636465666768010203040205070104'), packet('01020304bb000102')])
    conn = transport::Connection.new(descriptor: { protocol: :ctap }, io: io, timeout: 1)
    expect { conn.exchange(protocol: :ctap, command: 0x10, data: ''.b, on_keepalive: ->(_status) { raise Interrupt }) }.to raise_error(Interrupt)
    conn.close
    expect(io.writes.last).to eq(packet('01020304910000'))
    expect(io.closed).to eq(1)
  end

  it 'selects exact serial strings and never chooses the first of multiple keys' do
    records = [{ backend: :hid, protocol: :otp, serial: '0007', device_path: '/fake/one' },
               { backend: :hid, protocol: :otp, serial: '7', device_path: '/fake/two' }]
    native = double(devices: records)
    allow(transport).to receive(:native).with(kind: :hid).and_return(native)
    allow(native).to receive(:open) { raise 'must not open an ambiguous selection' }
    expect { transport.open(application: :otp) }.to raise_error(PWN::Plugins::YubiKey::Error, /multiple/i)
    expect { transport.open(application: :otp, serial: 7) }.to raise_error(ArgumentError, /serial/)
    io = fake_io
    allow(native).to receive(:open).with(records.first).and_return(io)
    conn = transport.open(application: :otp, serial: '0007')
    expect(conn.descriptor[:serial]).to eq('0007')
    conn.close
  end

  it 'selects serial-less Security Keys by path and reader-selected OTP over PC/SC' do
    hid = double(devices: [{ backend: :hid, protocol: :ctap, serial: nil, device_path: '/fake/security-key' }])
    pcsc = double(devices: [{ backend: :pcsc, protocol: :apdu, serial: nil, reader: 'NFC test reader' }])
    allow(transport).to receive(:native).with(kind: :hid).and_return(hid)
    allow(transport).to receive(:native).with(kind: :pcsc).and_return(pcsc)
    allow(SecureRandom).to receive(:random_bytes).with(8).and_return('abcdefgh')
    allow(hid).to receive(:open).and_return(fake_io(packets: [packet('ffffffff8600116162636465666768010203040205070104')]))
    allow(pcsc).to receive(:open).and_return(fake_io)
    conn = transport.open(application: :fido, device_path: '/fake/security-key')
    expect(conn.descriptor[:protocol]).to eq(:ctap)
    conn.close
    conn = transport.open(application: :otp, reader: 'NFC test reader')
    expect(conn.descriptor[:protocol]).to eq(:apdu)
    conn.close
  end

  it 'enumerates PC/SC reader strings without connecting and releases its context' do
    lib = fake_hid_library
    allow(lib).to receive(:ffi_libraries).and_return([double(find_symbol: FFI::Pointer.new(1))])
    native = transport::NativeLibrary.new(:pcsc, library: lib, platform: :linux)
    names = "Yubico YubiKey test\0NFC test\0\0".b
    expect(lib).to receive(:SCardEstablishContext) { |_, _, _, ptr|
      ptr.write_long(123)
      0
    }
    expect(lib).to(receive(:SCardListReaders).with(123, nil, nil, anything).ordered do |_, _, _, len|
      len.write_ulong(names.bytesize)
      0
    end)
    expect(lib).to(receive(:SCardListReaders).with(123, nil, kind_of(FFI::MemoryPointer), anything).ordered do |_, _, ptr, len|
      ptr.put_bytes(0, names)
      len.write_ulong(names.bytesize)
      0
    end)
    expect(lib).to receive(:SCardReleaseContext).with(123).ordered.and_return(0)
    expect(lib).not_to receive(:SCardConnect)
    expect(native.devices.map { |entry| entry[:reader] }).to eq(['Yubico YubiKey test', 'NFC test'])
  end

  it 'resolves a PC/SC serial using read-only OTP APDUs and rejects alternate spellings' do
    entry = { backend: :pcsc, protocol: :apdu, reader: 'Yubico YubiKey synthetic', serial: nil }
    binding = double(devices: [entry])
    allow(transport).to receive(:native).with(kind: :pcsc).and_return(binding)
    io = fake_io
    allow(binding).to receive(:open).and_return(io)
    expect(io).to receive(:transmit).with(['00a4040007a0000005272001'].pack('H*')).and_return(['0507010900009000'].pack('H*'))
    expect(io).to receive(:transmit).with(['0001100000'].pack('H*')).and_return(['000000079000'].pack('H*'))
    conn = transport.open(application: :piv, reader: entry[:reader], serial: '7')
    expect(conn.descriptor[:serial]).to eq('7')
    conn.close
    expect(io.closed).to eq(1)
  end

  it 'does not accept an unobservable PC/SC serial or coerce leading zero selectors' do
    entry = { backend: :pcsc, protocol: :apdu, reader: 'Yubico YubiKey synthetic', serial: nil }
    binding = double(devices: [entry])
    allow(transport).to receive(:native).with(kind: :pcsc).and_return(binding)
    io = fake_io
    allow(binding).to receive(:open).and_return(io)
    allow(io).to receive(:transmit).and_return(['9000'].pack('H*'), ['000000079000'].pack('H*'))
    expect { transport.open(application: :piv, reader: entry[:reader], serial: '0007') }.to raise_error(PWN::Plugins::YubiKey::Error, /serial|matching/i)
    expect(io.closed).to eq(1)
  end

  it 'finds a PC/SC serial through management when the OTP applet is disabled' do
    require 'pwn/plugins/yubikey/protocol'
    entry = { backend: :pcsc, protocol: :apdu, reader: 'NFC test reader', serial: nil }
    io = fake_io
    binding = double(devices: [entry], open: io)
    allow(transport).to receive(:native).with(kind: :pcsc).and_return(binding)
    expect(io).to receive(:transmit).with(['00a4040007a0000005272001'].pack('H*')).ordered.and_return(['6a82'].pack('H*'))
    expect(io).to receive(:transmit).with(['00a4040008a000000527471117'].pack('H*')).ordered.and_return("5.7.1\x90\0".b)
    expect(io).to receive(:transmit).with(['001d000000'].pack('H*')).ordered.and_return(['060204000000079000'].pack('H*'))
    conn = transport.open(application: :piv, reader: entry[:reader], serial: '7')
    expect(conn.descriptor[:serial]).to eq('7')
    conn.close
    expect(io.closed).to eq(1)
  end

  it 'binds HIDAPI lazily using a fake FFI shared-library boundary' do
    ffi_library = Module.new
    allow(ffi_library).to receive(:extend)
    expect(ffi_library).to receive(:ffi_lib).with(kind_of(Array))
    expect(ffi_library).to receive(:attach_function).with(:hid_init, [], :int, blocking: true)
    allow(ffi_library).to receive(:attach_function)
    expect(ffi_library).not_to receive(:hid_init)
    expect(ffi_library).not_to receive(:hid_enumerate)
    bound = transport::NativeLibrary.new(:hid, library: ffi_library, platform: :linux)
    expect(bound.library).to eq(ffi_library)
  end

  it 'probes native library symbols without initializing or discovering hardware' do
    library = double('native shared library')
    expect(library).not_to receive(:hid_init)
    expect(library).not_to receive(:hid_enumerate)
    expect(library).not_to receive(:SCardEstablishContext)
    allow(transport).to receive(:native).with(kind: :hid).and_return(library)
    expect(transport.available?(backend: :hid)).to be(true)
  end
end

RSpec.describe 'PWN::Plugins::YubiKey::Transport dependency and lifetime safety' do
  include_context 'native YubiKey wire fixtures'

  it 'documents its public selectors, protocol contract and driver timeout limit' do
    expect { transport.help }.to output(/available\?.*devices.*open.*driver/m).to_stdout
    expect(transport.authors).to include('0day Inc.')
  end

  it 'probes only PC/SC for an APDU-only application and never initializes hardware' do
    expect(transport).to receive(:native).with(kind: :pcsc).and_return(double('loaded PC/SC symbols'))
    expect(transport).not_to receive(:native).with(kind: :hid)
    expect(transport.available?(application: :piv)).to be(true)
  end

  it 'rejects explicit false backend and application selectors before any native lookup' do
    expect(transport).not_to receive(:native)
    expect { transport.available?(backend: false) }.to raise_error(ArgumentError)
    expect { transport.available?(application: false) }.to raise_error(ArgumentError)
    expect { transport.devices(backend: false) }.to raise_error(ArgumentError)
  end

  it 'reports absent shared libraries without touching an initialization entry point' do
    lib = fake_hid_library
    allow(lib).to receive(:ffi_lib).and_raise(LoadError, 'synthetic absence')
    expect(lib).not_to receive(:hid_init)
    expect { transport::NativeLibrary.new(:hid, library: lib) }.to raise_error(PWN::Plugins::YubiKey::DependencyError, /HIDAPI/)
    allow(transport).to receive(:native).and_raise(PWN::Plugins::YubiKey::DependencyError, 'missing native library')
    expect(transport.available?).to be(false)
    expect { transport.devices }.to raise_error(PWN::Plugins::YubiKey::DependencyError)
  end

  it 'balances HIDAPI initialization when a selected path cannot be opened' do
    native = transport::NativeLibrary.new(:hid, library: fake_hid_library)
    expect(native.library).to receive(:hid_init).and_return(0)
    expect(native.library).to receive(:hid_open_path).and_return(FFI::Pointer::NULL)
    expect(native.library).not_to receive(:hid_close)
    expect(native.library).to receive(:hid_exit).and_return(0)
    expect { native.open({ device_path: '/fake/unavailable' }) }.to raise_error(PWN::Plugins::YubiKey::CommandError, /permissions/)
  end

  it 'does not exit HIDAPI while another handle still owns a reference' do
    native = transport::NativeLibrary.new(:hid, library: fake_hid_library)
    lib = native.library
    one = FFI::MemoryPointer.new(:char)
    two = FFI::MemoryPointer.new(:char)
    expect(lib).to receive(:hid_init).once.and_return(0)
    expect(lib).to receive(:hid_open_path).with('/fake/1').and_return(one)
    expect(lib).to receive(:hid_open_path).with('/fake/2').and_return(two)
    expect(lib).to receive(:hid_close).with(one).ordered
    expect(lib).to receive(:hid_close).with(two).ordered
    expect(lib).to receive(:hid_exit).ordered.and_return(0)
    first = native.open({ device_path: '/fake/1' })
    second = native.open({ device_path: '/fake/2' })
    first.close
    second.close
  end

  it 'decodes Windows UTF-16 surrogate pairs and Unix wchar strings without stripping serials' do
    { windows: :uint16, linux: :uint32, macos: :uint32 }.each do |platform, type|
      native = transport::NativeLibrary.new(:hid, library: fake_hid_library, platform: platform)
      value = " 00\u{1f511} "
      units = type == :uint16 ? value.encode(Encoding::UTF_16LE).unpack('v*') : value.codepoints
      memory = FFI::MemoryPointer.new(type, units.length + 1)
      memory.public_send(:"write_array_of_#{type}", units + [0])
      expect(transport::HIDInventory.new(native).send(:wide_string, memory)).to eq(value)
    end
  end

  it 'releases a PC/SC context after an exclusive connect failure without disconnecting an invalid handle' do
    lib = fake_hid_library
    allow(lib).to receive(:ffi_libraries).and_return([double(find_symbol: FFI::Pointer.new(1))])
    native = transport::NativeLibrary.new(:pcsc, library: lib, platform: :linux)
    expect(lib).to receive(:SCardEstablishContext) { |_, _, _, ptr|
      ptr.write_long(123)
      0
    }
    expect(lib).to receive(:SCardConnect).and_return(0x8010000b)
    expect(lib).not_to receive(:SCardDisconnect)
    expect(lib).to receive(:SCardReleaseContext).with(123).and_return(0)
    expect { native.open({ reader: 'Yubico YubiKey fixture' }) }.to raise_error(PWN::Plugins::YubiKey::CommandError, /exclusive/)
  end

  it 'rejects unknown applications, conflicting selectors and empty discovery without choosing another reader' do
    binding = double(devices: [])
    allow(transport).to receive(:native).and_return(binding)
    expect(binding).not_to receive(:open)
    expect { transport.open(application: :unknown) }.to raise_error(ArgumentError)
    expect { transport.open(application: :piv, reader: 'one', device_path: 'two') }.to raise_error(ArgumentError)
    expect { transport.open(application: :fido) }.to raise_error(PWN::Plugins::YubiKey::Error, /No matching/)
    allow(binding).to receive(:devices).and_return([{ backend: :pcsc, protocol: :apdu, reader: 'Other card', serial: nil }])
    expect { transport.open(application: :piv) }.to raise_error(PWN::Plugins::YubiKey::Error, /No matching/)
    expect { transport.open(application: :piv, reader: 'missing') }.to raise_error(PWN::Plugins::YubiKey::Error, /No matching/)
  end

  it 'attempts every handle cleanup when ambiguous serial probes encounter a close failure' do
    entries = [1, 2].map { |number| { backend: :pcsc, protocol: :apdu, reader: "Yubico YubiKey fixture #{number}", serial: nil } }
    first = fake_io
    second = fake_io
    [first, second].each do |io|
      allow(io).to receive(:transmit).and_return(['9000'].pack('H*'), ['000000079000'].pack('H*'))
    end
    allow(first).to receive(:close).and_wrap_original do |method|
      method.call
      raise IOError, 'synthetic close failure'
    end
    binding = double(devices: entries)
    allow(binding).to receive(:open).and_return(first, second)
    allow(transport).to receive(:native).with(kind: :pcsc).and_return(binding)
    expect { transport.open(application: :piv, serial: '7') }.to raise_error(PWN::Plugins::YubiKey::Error, /Multiple/)
    expect([first.closed, second.closed]).to eq([1, 1])
  end

  it 'uses bounded HIDAPI reads and zero report IDs for OTP writes at the native boundary' do
    native = transport::NativeLibrary.new(:hid, library: fake_hid_library)
    lib = native.library
    handle = FFI::MemoryPointer.new(:char)
    expect(lib).to receive(:hid_init).and_return(0)
    expect(lib).to receive(:hid_open_path).and_return(handle)
    expect(lib).to receive(:hid_read_timeout).with(handle, anything, 64, 17) do |_, buffer, _, _|
      buffer.put_bytes(0, packet('0102030490000100'))
      64
    end
    expect(lib).to receive(:hid_send_feature_report).with(handle, anything, 9) do |_, buffer, length|
      expect(buffer.read_bytes(length)).to eq(['0000000000000000ff'].pack('H*'))
      9
    end
    expect(lib).to receive(:hid_close).with(handle)
    expect(lib).to receive(:hid_exit).and_return(0)
    io = native.open({ device_path: '/fake/hid' })
    expect(io.read_packet(17)).to eq(packet('0102030490000100'))
    io.write_feature(['00000000000000ff'].pack('H*'))
    io.close
  end

  it 'rejects partial HID writes and truncated input reports without retrying the C call' do
    native = transport::NativeLibrary.new(:hid, library: fake_hid_library)
    lib = native.library
    handle = FFI::MemoryPointer.new(:char)
    allow(lib).to receive(:hid_init).and_return(0)
    allow(lib).to receive(:hid_open_path).and_return(handle)
    expect(lib).to receive(:hid_write).once.and_return(64)
    expect(lib).to receive(:hid_read_timeout).once.and_return(63)
    expect(lib).to receive(:hid_get_feature_report).once.and_return(8)
    expect(lib).to receive(:hid_close).with(handle)
    expect(lib).to receive(:hid_exit).and_return(0)
    io = native.open({ device_path: '/fake/hid' })
    expect { io.write_packet(packet('0102030490000100')) }.to raise_error(PWN::Plugins::YubiKey::CommandError, /incomplete/)
    expect { io.read_packet(20) }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /length/)
    expect { io.read_feature }.to raise_error(PWN::Plugins::YubiKey::ResponseError, /length/)
    io.close
  end

  it 'closes an acquired native handle that arrives after its opening deadline' do
    release = Queue.new
    cleaned = Queue.new
    io = fake_io
    allow(io).to(receive(:close).and_wrap_original do |method|
      method.call
      cleaned << true
    end)
    entry = { backend: :hid, protocol: :otp, serial: '7', device_path: '/fake/late' }
    binding = double(devices: [entry])
    allow(binding).to receive(:open) {
      release.pop
      io
    }
    allow(transport).to receive(:native).with(kind: :hid).and_return(binding)
    expect { transport.open(application: :otp, serial: '7', timeout: 0.03) }.to raise_error(PWN::Plugins::YubiKey::TimeoutError)
    expect(io.closed).to eq(0)
    release << true
    expect(cleaned.pop(timeout: 1)).to be(true)
    expect(io.closed).to eq(1)
  ensure
    release << true if release
  end

  it 'keeps the public discovery waiter bounded while the native enumerator still owns its resources' do
    release = Queue.new
    cleaned = Queue.new
    binding = double
    allow(binding).to receive(:devices) do
      release.pop
      []
    ensure
      cleaned << true
    end
    allow(transport).to receive(:native).with(kind: :hid).and_return(binding)
    expect { transport.devices(backend: :hid, timeout: 0.03) }.to raise_error(PWN::Plugins::YubiKey::TimeoutError)
    expect(cleaned.empty?).to be(true)
    release << true
    expect(cleaned.pop(timeout: 1)).to be(true)
  ensure
    release << true if release
  end

  it 'requires exact Windows wide reader names and uint32 reader-list lengths' do
    lib = fake_hid_library
    allow(lib).to receive(:ffi_convention)
    allow(lib).to receive(:ffi_libraries).and_return([double(find_symbol: FFI::Pointer.new(1))])
    expect(lib).to receive(:attach_function).with(:SCardListReaders, :SCardListReadersW, %i[uintptr_t pointer pointer pointer], :int32, blocking: true)
    native = transport::NativeLibrary.new(:pcsc, library: lib, platform: :windows)
    names = "NFC \u{1f511}\0\0".encode(Encoding::UTF_16LE).b
    expect(lib).to receive(:SCardEstablishContext) do |_, _, _, pointer|
      pointer.write(:uintptr_t, 123)
      0
    end
    expect(lib).to receive(:SCardListReaders).with(123, nil, nil, anything) do |_, _, _, length|
      length.write_uint32(names.bytesize / 2)
      0
    end
    expect(lib).to receive(:SCardListReaders).with(123, nil, kind_of(FFI::MemoryPointer), anything) do |_, _, buffer, length|
      buffer.put_bytes(0, names)
      length.write_uint32(names.bytesize / 2)
      0
    end
    expect(lib).to receive(:SCardReleaseContext).with(123).and_return(0)
    expect(native.devices.first[:reader]).to eq("NFC \u{1f511}")
  end

  it 'rejects simultaneous exchanges instead of interleaving packets and closes after the active call' do
    entered = Queue.new
    release = Queue.new
    io = fake_io
    allow(io).to receive(:transmit) { |_data|
      entered << true
      release.pop
      "\x90\0".b
    }
    conn = transport::Connection.new(descriptor: { protocol: :apdu }, io: io, timeout: 1)
    first = Thread.new { conn.exchange(protocol: :apdu, data: 'abcd') }
    entered.pop
    expect { conn.exchange(protocol: :apdu, data: 'abcd') }.to raise_error(PWN::Plugins::YubiKey::CommandError, /active/)
    release << true
    expect(first.value).to eq("\x90\0".b)
    conn.close
    expect(io.closed).to eq(1)
  ensure
    release << true if release
    first&.join(1)
    conn&.close
  end
end

RSpec.describe 'PWN::Plugins::YubiKey::Transport framing failures and limits' do
  include_context 'native YubiKey wire fixtures'

  let(:init_reply) { packet('ffffffff8600116162636465666768010203040205070104') }
  let(:status) { ['0005070109000000'].pack('H*') }

  before { allow(SecureRandom).to receive(:random_bytes).with(8).and_return('abcdefgh') }

  it 'rejects reserved CTAPHID control commands before any device I/O' do
    [0x06, 0x11, 0x3b, 0x3f].each do |command|
      io = fake_io
      conn = transport::Connection.new(descriptor: { protocol: :ctap }, io: io, timeout: 0.02)
      expect { conn.exchange(protocol: :ctap, command: command, data: ''.b) }.to raise_error(ArgumentError, /reserved/)
      expect(io.writes).to be_empty
      conn.close
    end
  end

  it 'rejects a status-only OTP reply when a checked data response was required' do
    io = fake_io(features: [status, status, status, ['000507010a010000'].pack('H*')])
    conn = transport::Connection.new(descriptor: { protocol: :otp }, io: io)
    expect { conn.exchange(protocol: :otp, command: 0x10, data: ''.b, response_length: 4) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
    expect(io.closed).to eq(1)
  end

  it 'exposes CTAPHID INIT capabilities before returning an opened FIDO connection' do
    entry = { backend: :hid, protocol: :ctap, device_path: '/fake/security-key', serial: nil }
    io = fake_io(packets: [init_reply])
    binding = double(devices: [entry], open: io)
    allow(transport).to receive(:native).with(kind: :hid).and_return(binding)
    conn = transport.open(application: :fido, device_path: entry[:device_path], timeout: 1)
    expect(conn.descriptor).to include(version: [5, 7, 1], capabilities: 4)
    expect(io.writes).to eq([packet('ffffffff8600086162636465666768')])
    conn.close
  end

  {
    nonce: 'ffffffff8600116162636465666769010203040205070104',
    channel: 'ffffffff8600116162636465666768ffffffff0205070104',
    version: 'ffffffff8600116162636465666768010203040105070104',
    length: 'ffffffff86001061626364656667680102030402050701'
  }.each do |label, hex|
    it "rejects a CTAPHID INIT with invalid #{label} and closes the handle" do
      io = fake_io(packets: [packet(hex)])
      conn = transport::Connection.new(descriptor: { protocol: :ctap }, io: io, timeout: 0.5)
      expect { conn.exchange(protocol: :ctap, command: 1, data: ''.b) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
      expect(io.closed).to eq(1)
      expect(io.writes.length).to eq(1)
    end
  end

  it 'ignores unrelated channels and reports keepalive while preserving the binary CTAP status byte' do
    io = fake_io(packets: [init_reply, packet('0506070890000101'), packet('01020304bb000102'), packet('0102030490000300a100')])
    conn = transport::Connection.new(descriptor: { protocol: :ctap }, io: io)
    statuses = []
    expect(conn.exchange(protocol: :ctap, command: 0x10, data: ''.b, on_keepalive: ->(value) { statuses << value })).to eq(['00a100'].pack('H*'))
    expect(statuses).to eq([2])
    conn.close
  end

  {
    sequence: ["0102030490003c#{'00' * 57}", '0102030401000000'],
    oversized: ['01020304901dba'],
    keepalive: ['01020304bb000103'],
    command: ['01020304810000']
  }.each do |label, response|
    it "rejects malformed CTAPHID #{label} without replaying the request" do
      io = fake_io(packets: [init_reply] + response.map { |hex| packet(hex) })
      conn = transport::Connection.new(descriptor: { protocol: :ctap }, io: io)
      expect { conn.exchange(protocol: :ctap, command: 0x10, data: ''.b) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
      expect(io.writes.map { |wire| wire.getbyte(4) }).to eq([0x86, 0x90, 0x91])
      expect(io.closed).to eq(1)
    end
  end

  it 'raises CTAPHID busy errors without an implicit retry of an uncertain command' do
    io = fake_io(packets: [init_reply, packet('01020304bf000106')])
    conn = transport::Connection.new(descriptor: { protocol: :ctap }, io: io)
    expect { conn.exchange(protocol: :ctap, command: 0x10, data: ''.b) }.to raise_error(PWN::Plugins::YubiKey::CommandError, /0x06/)
    expect(io.writes.count { |wire| wire.getbyte(4) == 0x90 }).to eq(1)
    expect(io.closed).to eq(1)
  end

  it 'frames the full 7609-byte CTAPHID limit without wrapping continuation numbers' do
    io = fake_io(packets: [init_reply, packet('01020304810000')])
    conn = transport::Connection.new(descriptor: { protocol: :ctap }, io: io)
    expect(conn.exchange(protocol: :ctap, command: 1, data: 'Z' * 7609)).to eq(''.b)
    expect(io.writes.length).to eq(130)
    expect(io.writes[1]).to eq(packet("01020304811db9#{'5a' * 57}"))
    expect(io.writes.last).to eq(packet("010203047f#{'5a' * 59}"))
    conn.close
  end

  it 'waits for OTP touch then validates a fixed data CRC' do
    io = fake_io(features: [status, status, status, ['0000000000000020'].pack('H*'), ['0001020329a70040'].pack('H*'), ['0000000000000040'].pack('H*')])
    conn = transport::Connection.new(descriptor: { protocol: :otp }, io: io)
    statuses = []
    expect(conn.exchange(protocol: :otp, command: 0x10, data: ''.b, response_length: 4, on_keepalive: ->(value) { statuses << value })).to eq(['00010203'].pack('H*'))
    expect(statuses).to eq([2])
    conn.close
  end

  it 'aborts the OTP touch state when the cancellation predicate becomes true' do
    io = fake_io(features: [status, status, status, ['0000000000000020'].pack('H*')])
    conn = transport::Connection.new(descriptor: { protocol: :otp }, io: io)
    stopped = false
    expect do
      conn.exchange(protocol: :otp, command: 0x10, data: ''.b, response_length: 4,
                    on_keepalive: ->(_value) { stopped = true }, cancelled: -> { stopped })
    end.to raise_error(transport::CancelledError)
    expect(io.feature_writes.last).to eq(['00000000000000ff'].pack('H*'))
    expect(io.closed).to eq(1)
  end

  {
    crc: %w[0001020328a70040 0000000000000040],
    sequence: %w[0001020329a70041],
    truncated: %w[0001020329a70040 0005070109000000]
  }.each do |label, response|
    it "rejects an OTP #{label} fault and resets the device state" do
      io = fake_io(features: [status, status, status] + response.map { |hex| [hex].pack('H*') })
      conn = transport::Connection.new(descriptor: { protocol: :otp }, io: io)
      expect { conn.exchange(protocol: :otp, command: 0x10, data: ''.b, response_length: 4) }.to raise_error(PWN::Plugins::YubiKey::ResponseError)
      expect(io.feature_writes.last).to eq(['00000000000000ff'].pack('H*'))
      expect(io.closed).to eq(1)
    end
  end

  it 'returns programming status only after the sequence increments or the last slot is deleted' do
    %w[000507010a010000 0005070100000000].each do |updated|
      io = fake_io(features: [status, status, status, [updated].pack('H*')])
      conn = transport::Connection.new(descriptor: { protocol: :otp }, io: io)
      expect(conn.exchange(protocol: :otp, command: 1, data: ''.b)).to eq([updated].pack('H*').byteslice(1, 6))
      conn.close
    end
  end

  it 'does not accept a zero programming sequence while a slot still reports programmed' do
    previous = ['00050701ff010000'].pack('H*')
    io = fake_io(features: [previous, previous, previous, ['0005070100010000'].pack('H*')])
    conn = transport::Connection.new(descriptor: { protocol: :otp }, io: io)
    expect { conn.exchange(protocol: :otp, command: 1, data: ''.b) }.to raise_error(PWN::Plugins::YubiKey::CommandError)
    expect(io.closed).to eq(1)
  end

  it 'bounds the OTP busy writer without sending the application payload' do
    io = fake_io(features: [status])
    allow(io).to receive(:read_feature).and_return(status, ['0005070109000080'].pack('H*'))
    conn = transport::Connection.new(descriptor: { protocol: :otp }, io: io, timeout: 0.03)
    expect { conn.exchange(protocol: :otp, command: 1, data: ''.b) }.to raise_error(PWN::Plugins::YubiKey::TimeoutError)
    expect(io.feature_writes).to eq([['00000000000000ff'].pack('H*')])
    expect(io.closed).to eq(1)
  end

  it 'rejects invalid protocol, sizes, callbacks and nonfinite deadlines before I/O' do
    %i[ctap otp apdu].each do |protocol|
      limit = { ctap: 7609, otp: 64, apdu: 65_544 }.fetch(protocol)
      io = fake_io
      conn = transport::Connection.new(descriptor: { protocol: protocol }, io: io)
      expect { conn.exchange(protocol: protocol, command: 1, data: 'x' * (limit + 1)) }.to raise_error(ArgumentError)
      expect { conn.exchange(protocol: :other, command: 1, data: 'data') }.to raise_error(ArgumentError)
      [true, false].each do |callback|
        expect { conn.exchange(protocol: protocol, command: 1, data: 'data', on_keepalive: callback, timeout: 0.02) }.to raise_error(ArgumentError)
        expect { conn.exchange(protocol: protocol, command: 1, data: 'data', cancelled: callback) }.to raise_error(ArgumentError)
      end
      [0, -1, Float::NAN, Float::INFINITY, '1'].each do |timeout|
        expect { conn.exchange(protocol: protocol, command: 1, data: 'data', timeout: timeout) }.to raise_error(ArgumentError)
      end
      expect(io.writes + io.feature_writes).to be_empty
      conn.close
    end
  end
end
