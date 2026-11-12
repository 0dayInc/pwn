# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::SBOM do
  before do
    load File.expand_path('../../../../lib/pwn/ai/agent/tools/sbom_scan.rb', __dir__)
  end

  %w[grype trivy osv-scanner syft].each do |engine|
    it "[PBR-06] propagates fatal #{engine} errors through the real registered handler" do
      allow(Open3).to receive(:capture2).and_return(['{"error":"SYNTHETIC-PRIVATE-ENGINE"}', instance_double(Process::Status, success?: false, exitstatus: 2)])
      handler = PWN::AI::Agent::Registry.lookup(name: 'sbom_scan')[:handler]
      row = handler.call('engine' => engine, 'path' => 'fixture')
      expect(row[:error] || row[:status] == 'failed' || row[:success] == false).to be_truthy
      expect(row[:error].to_s).not_to include('SYNTHETIC-PRIVATE-ENGINE')
    end
  end

  { 'grype' => 'matches', 'trivy' => 'Results', 'osv-scanner' => 'results', 'syft' => 'artifacts' }.each do |engine, key|
    it "[PBR-06] retains valid empty #{engine} results" do
      allow(Open3).to receive(:capture2).and_return([JSON.generate(key => []), instance_double(Process::Status, success?: true, exitstatus: 0)])
      allow(PWN::Plugins::PreflightChecker).to receive(:bin?).and_return(false)
      expect(described_class.scan(path: 'fixture', engine: engine)[:vulns]).to eq([])
    end

    ['{"error":"SYNTHETIC-PRIVATE-ENGINE"}', '{"SYNTHETIC-PRIVATE-ENGINE":', '[]', '{"matches":42}'].each do |body|
      it "[PBR-06] rejects #{engine} malformed/error envelopes without raw parser causes: #{body.length}" do
        allow(Open3).to receive(:capture2).and_return([body, instance_double(Process::Status, success?: true, exitstatus: 0)])
        allow(PWN::Plugins::PreflightChecker).to receive(:bin?).and_return(false)
        row = described_class.scan(path: 'fixture', engine: engine)
        expect(row[:success]).to be(false)
        expect(row[:error].to_s).not_to include('SYNTHETIC-PRIVATE-ENGINE')
      end
    end
  end

  it '[PBR-06] accepts the OSV vulnerability-found exit with a valid response' do
    body = { results: [{ packages: [{ package: { name: 'fixture', version: '1' }, vulnerabilities: [{ id: 'CVE-fixture' }] }] }] }
    allow(Open3).to receive(:capture2).and_return([JSON.generate(body), instance_double(Process::Status, success?: false, exitstatus: 1)])
    expect(described_class.scan(path: 'fixture', engine: 'osv-scanner')[:vulns].first[:cve]).to eq('CVE-fixture')
  end
end
