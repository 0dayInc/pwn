# frozen_string_literal: true

require 'spec_helper'
require 'ffi'

RSpec.describe PWN::Setup, 'native library doctor' do
  around do |example|
    Dir.mktmpdir('native-library-doctor-') do |root|
      @root = root
      example.run
    end
  end

  before do
    allow(Dir).to receive(:home).and_return(@root)
    stub_const('PWN::Env', {})
    allow(PWN::Migrate).to receive(:check).and_return(incompatible: [])
    allow(described_class).to receive(:pkg_manager).and_return(key: :apt, install: 'install-package')
    allow(described_class).to receive(:which).and_return('/fixture/bin')
    allow(described_class).to receive(:gem_loadable?).and_return(true)
    allow(described_class).to receive(:detect_os_attr).with(attr: :type, fallback: anything).and_return(:linux)
    allow(described_class).to receive(:detect_os_attr).with(attr: :arch, fallback: anything).and_return('fixture')
    allow(FFI::DynamicLibrary).to receive(:open).and_raise(LoadError, 'fixture library missing')
    device = double('untouched native device')
    stub_const('PWN::Plugins::YubiKey', device)
    %i[devices info command challenge_response oath_code].each { |method| expect(device).not_to receive(method) }
  end

  it 'reports missing optional libraries but gates only hardware and full profiles on them' do
    %i[core hardware full].each do |profile|
      io = StringIO.new
      report = described_class.check(profile: profile, io: io)
      expect(report[:ok]).to eq(profile == :core)
      expect(report[:native_libraries_missing]).to eq(%w[hidapi pcsc])
      expect(report[:native_gems_missing]).to eq([])
      expect(report[:toolchain_missing]).to eq([])
      expect(io.string).to include('Native libraries', 'hidapi', 'pcsc', 'no device discovery')
    end
  end

  it 'loads only library handles and accepts the alternative HIDAPI libusb backend' do
    flags = FFI::DynamicLibrary::RTLD_LAZY | FFI::DynamicLibrary::RTLD_LOCAL
    allow(FFI::DynamicLibrary).to receive(:open).with('libhidapi-libusb.so.0', flags).and_return(double('HID library'))
    allow(FFI::DynamicLibrary).to receive(:open).with('libpcsclite.so.1', flags).and_return(double('PCSC library'))
    report = described_class.check(profile: :hardware, io: StringIO.new)
    expect(report[:ok]).to be(true)
    expect(report[:native_libraries_missing]).to eq([])
    expect(FFI::DynamicLibrary).to have_received(:open).with('libhidapi-hidraw.so.0', flags)
  end

  it 'recognizes the built-in macOS PCSC framework and Homebrew HIDAPI path' do
    allow(described_class).to receive(:detect_os_attr).with(attr: :type, fallback: anything).and_return(:osx)
    flags = FFI::DynamicLibrary::RTLD_LAZY | FFI::DynamicLibrary::RTLD_LOCAL
    allow(FFI::DynamicLibrary).to receive(:open).with('/System/Library/Frameworks/PCSC.framework/PCSC', flags).and_return(double('system PCSC framework'))
    allow(FFI::DynamicLibrary).to receive(:open).with('/opt/homebrew/lib/libhidapi.dylib', flags).and_return(double('HID library'))
    report = described_class.check(profile: :hardware, io: StringIO.new)
    expect(report[:ok]).to be(true)
    expect(report[:native_libraries_missing]).to eq([])
  end

  it 'lists optional native libraries in profile descriptions' do
    io = StringIO.new
    described_class.list_profiles(io: io)
    expect(io.string).to include('libs: hidapi pcsc')
  end
end
