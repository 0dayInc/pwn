# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::SBOM do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'normalizes grype JSON into package/cve rows' do
    json = { 'matches' => [{ 'artifact' => { 'name' => 'openssl', 'version' => '1.1.1' },
                             'vulnerability' => { 'id' => 'CVE-2024-0001', 'severity' => 'HIGH', 'fix' => { 'versions' => ['1.1.1w'] } } }] }
    allow(Open3).to receive(:capture2).and_return([JSON.generate(json), instance_double(Process::Status, success?: true)])
    allow(PWN::Plugins::PreflightChecker).to receive(:bin?).and_return(true)
    out = described_class.scan(path_or_image: '/tmp/lock', engine: 'grype')
    expect(out[:vulns].first).to include(package: 'openssl', cve: 'CVE-2024-0001', severity: 'high', fix_version: '1.1.1w')
  end
end
