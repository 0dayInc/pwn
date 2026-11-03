# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Setup, 'optional native YubiKey libraries' do
  before do
    allow(described_class).to receive(:check).and_return(ok: true)
    allow(described_class).to receive(:gem_loadable?).and_return(true)
    expect(described_class).not_to receive(:system)
  end

  it 'replaces executable provisioning with optional HIDAPI and PC/SC libraries' do
    expect(described_class::TOOLCHAIN).not_to have_key('ykman')
    expect(described_class::PROFILES.fetch(:hardware).fetch(:bins)).not_to include('ykman')
    expect(described_class::PROFILES.fetch(:full).fetch(:bins)).not_to include('ykman')
    expect(described_class::PROFILES.fetch(:hardware).fetch(:libs)).to eq(%w[hidapi pcsc])
    expect(described_class::PROFILES.fetch(:full).fetch(:libs)).to eq(described_class::NATIVE_LIBRARIES.keys)
    expect(Array(described_class::PROFILES.fetch(:core)[:libs])).to be_empty
  end

  { apt: %w[libhidapi-hidraw0 libpcsclite1 pcscd libccid],
    dnf: %w[hidapi pcsc-lite-libs pcsc-lite pcsc-lite-ccid],
    pacman: %w[hidapi pcsclite ccid], brew: %w[hidapi], port: %w[hidapi] }.each do |manager, libraries|
    it "plans native host packages for #{manager} without a Python or CLI backend" do
      allow(described_class).to receive(:pkg_manager).and_return(key: manager, install: 'install-package')
      result = described_class.deps(profile: :hardware, dry_run: true, io: StringIO.new, distro: :fixture, version: 'test')
      commands = result.fetch(:ran).map { |row| row.fetch(:cmd) }
      libraries.each { |package| expect(commands).to include("install-package #{package}") }
      expect(commands.join('\n')).not_to match(/ykman|yubikey-manager|python|\bpip(?:[23x])?\b/)
      expect(result.fetch(:ran)).to all(include(dry_run: true))
      expect(commands.join('\n')).not_to match(/pcsc|ccid/) if %i[brew port].include?(manager)
    end
  end

  it 'does not install hardware packages in the core profile' do
    allow(described_class).to receive(:pkg_manager).and_return(key: :apt, install: 'install-package')
    result = described_class.deps(profile: :core, dry_run: true, io: StringIO.new, distro: :fixture, version: 'test')
    expect(result.fetch(:ran).map { |row| row.fetch(:cmd) }.join('\n')).not_to match(/hidapi|pcsclite|pcscd|ccid|ykman/)
  end
end
