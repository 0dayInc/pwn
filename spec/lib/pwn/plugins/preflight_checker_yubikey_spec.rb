# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::PreflightChecker, 'YubiKey dependency reporting' do
  let(:names) { ['PWN::Plugins::YubiKey'] }

  before do
    @device = double('unopened YubiKey')
    stub_const('PWN::Plugins::YubiKey', @device)
    %i[devices info command challenge_response oath_code].each { |method| expect(@device).not_to receive(method) }
    allow(@device).to receive(:available?).with({ application: :fido }).and_return(false)
    allow(@device).to receive(:available?).with({ application: :oath }).and_return(false)
    allow(described_class).to receive(:bin?).and_return(true)
    expect(described_class).not_to receive(:bin?).with(name: 'ykman')
  end

  it 'reports unavailable native host libraries without a binary requirement or device probe' do
    row = described_class.check(names: names).first
    expect(row).to include(plugin: names.first, status: :dead, missing_bins: [], missing_caps: [], missing_services: [])
    expect(row[:missing_native]).to eq(['FIDO native transport', 'PC/SC native transport'])
    expect(described_class.host_summary(names: names)).to include('PC/SC native transport', 'documentation/Plugin-Degradation.md#pwn-plugins-yubikey')
  end

  it 'reports partial native host capability separately from all libraries being available' do
    allow(@device).to receive(:available?).with({ application: :fido }).and_return(true)
    expect(described_class.check(names: names).first).to include(status: :degraded, missing_native: ['PC/SC native transport'])
    allow(@device).to receive(:available?).with({ application: :oath }).and_return(true)
    expect(described_class.check(names: names).first).to include(status: :ok, missing_bins: [], missing_native: [])
  end

  it 'preserves rows for plugins without declared native dependencies' do
    expected = { plugin: 'PWN::Plugins::NmapIt', status: :ok, missing_bins: [], missing_caps: [], missing_services: [] }
    expect(described_class.check(names: ['PWN::Plugins::NmapIt'])).to eq([expected])
  end

  it 'includes native dependency status in the manifest without changing other plugin rows' do
    Dir.mktmpdir('native-preflight-') do |root|
      allow(Dir).to receive(:home).and_return(root)
      result = described_class.manifest
      expect(result[:plugins].fetch(names.first)).to include(ok: false, missing: [], missing_native: ['FIDO native transport', 'PC/SC native transport'])
      expect(result[:plugins].fetch('PWN::Plugins::NmapIt')).to eq(bins: ['nmap'], missing: [], ok: true, caps: [])
      stored = JSON.parse(File.read(result.fetch(:path)))
      expect(stored.fetch('plugins').fetch(names.first).fetch('missing_native')).to eq(result[:plugins][names.first][:missing_native])
    end
  end

  it 'treats load or dependency errors as a missing host library without exposing backend messages' do
    [LoadError, IOError].each do |error|
      allow(@device).to receive(:available?).with({ application: :oath }).and_raise(error, 'private fixture path')
      expect(described_class.check(names: names).first).to include(status: :dead, missing_native: ['FIDO native transport', 'PC/SC native transport'])
      expect(described_class.host_summary(names: names)).not_to include('private fixture path')
    end
  end
end
