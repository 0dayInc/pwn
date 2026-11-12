# frozen_string_literal: true

require 'spec_helper'
require 'ffi'

RSpec.describe PWN::Plugins::YubiKey::Transport do
  it 'preserves enumeration cancellation over native release failure' do
    library = double('fake HID API')
    native = double('fake backend', acquire: nil, library: library)
    allow(library).to receive(:hid_enumerate).and_raise(Interrupt, 'primary cancellation')
    allow(native).to receive(:release).and_raise(IOError, 'secondary release failure')
    allow(native).to receive(:devices) { described_class::HIDInventory.new(native).devices }
    allow(described_class).to receive(:native).with(kind: :hid).and_return(native)
    expect { described_class.devices(backend: :hid) }.to raise_error(Interrupt, 'primary cancellation')
    expect(native).to have_received(:release).once
  end

  it 'preserves the first cleanup failure while still releasing the native library' do
    library = double('fake HID API')
    native = double('fake backend', acquire: nil, library: library)
    inventory = described_class::HIDInventory.new(native)
    entry = inventory.instance_variable_get(:@info).new
    allow(library).to receive(:hid_enumerate).and_return(entry.pointer)
    allow(library).to receive(:hid_free_enumeration).and_raise(IOError, 'first cleanup failure')
    allow(native).to receive(:release).and_raise(IOError, 'second cleanup failure')
    allow(native).to receive(:devices) { inventory.devices }
    allow(described_class).to receive(:native).with(kind: :hid).and_return(native)
    expect { described_class.devices(backend: :hid) }.to raise_error(IOError, 'first cleanup failure')
    expect(native).to have_received(:release).once
  end

  it 'surfaces cleanup-only errors inside an unrelated caller rescue' do
    library = double('fake HID API', hid_enumerate: FFI::Pointer::NULL)
    native = double('fake backend', acquire: nil, library: library)
    allow(native).to receive(:release).and_raise(IOError, 'release failure')
    inventory = described_class::HIDInventory.new(native)
    begin
      raise 'unrelated caller error'
    rescue RuntimeError
      expect { inventory.devices }.to raise_error(IOError, 'release failure')
    end
  end

  it 'returns an empty fake native inventory and releases it exactly once' do
    library = double('fake HID API', hid_enumerate: FFI::Pointer::NULL)
    native = double('fake backend', acquire: nil, library: library, release: nil)
    allow(native).to receive(:devices) { described_class::HIDInventory.new(native).devices }
    allow(described_class).to receive(:native).with(kind: :hid).and_return(native)
    expect(described_class.devices(backend: :hid)).to eq([])
    expect(native).to have_received(:release).once
  end
end
