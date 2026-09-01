# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::DetectOS do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  describe '.distro' do
    it 'returns a lowercase symbol on this host' do
      expect(described_class.distro).to be_a(Symbol)
    end

    it 'reads Kali from os-release including rolling versions like 2026.3' do
      body = <<~OS
        ID=kali
        VERSION_ID="2026.3"
        ID_LIKE=debian
      OS
      expect(described_class.distro(os_release: body, type: :linux)).to eq(:kali)
      expect(described_class.version(os_release: body, type: :linux)).to eq('2026.3')
    end

    it 'reads Ubuntu and Debian' do
      expect(described_class.distro(os_release: "ID=ubuntu\nVERSION_ID=\"24.04\"\n", type: :linux)).to eq(:ubuntu)
      expect(described_class.version(os_release: "ID=ubuntu\nVERSION_ID=\"24.04\"\n", type: :linux)).to eq('24.04')
      expect(described_class.distro(os_release: "ID=debian\nVERSION_ID=\"12\"\n", type: :linux)).to eq(:debian)
    end

    it 'reads Fedora, Arch, Alpine' do
      expect(described_class.distro(os_release: "ID=fedora\nVERSION_ID=41\n", type: :linux)).to eq(:fedora)
      expect(described_class.distro(os_release: "ID=arch\n", type: :linux)).to eq(:arch)
      expect(described_class.distro(os_release: "ID=alpine\nVERSION_ID=3.20.0\n", type: :linux)).to eq(:alpine)
    end

    it 'detects ChromeOS from lsb-release' do
      lsb = "CHROMEOS_RELEASE_NAME=Chrome OS\nCHROMEOS_RELEASE_VERSION=15662.64.0\n"
      expect(described_class.distro(lsb_release: lsb, os_release: "ID=chromeos\n", type: :linux)).to eq(:chromeos)
      expect(described_class.version(lsb_release: lsb, os_release: "ID=chromeos\n", type: :linux)).to eq('15662.64.0')
    end

    it 'detects Android from build.prop' do
      prop = "ro.build.version.release=14\nro.product.brand=google\n"
      expect(described_class.distro(build_prop: prop, type: :linux)).to eq(:android)
      expect(described_class.version(build_prop: prop, type: :linux)).to eq('14')
    end

    it 'detects macOS, iOS, Windows, and BSDs' do
      expect(described_class.distro(type: :osx, sw_vers: '15.1')).to eq(:macos)
      expect(described_class.version(type: :osx, sw_vers: '15.1')).to eq('15.1')
      expect(described_class.distro(type: :linux, platform: 'arm64-darwin-ios')).to eq(:ios)
      expect(described_class.distro(type: :windows, win_ver: 'Microsoft Windows [Version 10.0.26100.1742]')).to eq(:windows)
      expect(described_class.version(type: :windows, win_ver: 'Microsoft Windows [Version 10.0.26100.1742]')).to eq('10.0.26100.1742')
      expect(described_class.distro(type: :freebsd, uname: 'FreeBSD')).to eq(:freebsd)
      expect(described_class.version(type: :freebsd, uname_r: '14.1-RELEASE')).to eq('14.1-RELEASE')
      expect(described_class.distro(type: :openbsd, uname: 'OpenBSD')).to eq(:openbsd)
      expect(described_class.distro(type: :netbsd, uname: 'NetBSD')).to eq(:netbsd)
    end
  end

  describe '.living_off_the_land' do
    it 'profiles distro, arch, and which host bins are present from fixtures' do
      body = "ID=kali\nVERSION_ID=\"2026.3\"\n"
      row = described_class.living_off_the_land(
        os_release: body,
        type: :linux,
        which: { 'gdb' => true, 'r2' => true, 'nuclei' => false }
      )
      expect(row[:distro]).to eq(:kali)
      expect(row[:version]).to eq('2026.3')
      expect(row[:arch]).to be_a(String)
      expect(row[:endian]).to be_a(Symbol)
      expect(row[:present]).to include('gdb', 'r2')
      expect(row[:missing]).to include('nuclei')
      expect(row[:present]).not_to include('nuclei')
      expect(row[:summary]).to include('kali')
      expect(row[:summary]).to include('gdb')
    end

    it 'does not fall through to live os-release when fixtures are passed' do
      row = described_class.living_off_the_land(
        os_release: "ID=alpine\nVERSION_ID=3.20.0\n",
        type: :linux,
        which: {}
      )
      expect(row[:distro]).to eq(:alpine)
      expect(row[:version]).to eq('3.20.0')
    end

    it 'probes extra bins from opts without inventing a PATH dump' do
      row = described_class.living_off_the_land(
        os_release: "ID=debian\nVERSION_ID=12\n",
        type: :linux,
        bins: %w[jq],
        which: { 'jq' => true }
      )
      expect(row[:present]).to include('jq')
    end
  end
end
