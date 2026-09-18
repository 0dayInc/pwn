# frozen_string_literal: true

require 'spec_helper'

describe PWN::Plugins::Recon do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'crt_sh falls back to certspotter when crt.sh is not JSON' do
    html = '<html><head><title>502 Bad Gateway</title></head></html>'
    spot = [{ 'dns_names' => ['www.0dayinc.com', 'vpn.0dayinc.com'] }]
    allow(described_class).to receive(:http_json) do |h|
      url = h[:url].to_s
      raise JSON::ParserError, html if url.include?('crt.sh')

      spot
    end
    names = described_class.crt_sh(domain: '0dayinc.com')
    expect(names).to include('www.0dayinc.com', 'vpn.0dayinc.com')
  end

  it 'harvests recon banners into the loot store' do
    Dir.mktmpdir('pwn-recon-loot-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      described_class.harvest_loot(
        engagement_id: 'lab',
        assets: [{
          address: 'app.example.test',
          observations: [{ banner: "SSH-2.0\nusername=admin\npassword=hunter2\n" }]
        }]
      )
      offered = PWN::Plugins::Vault.offer(host: 'app.example.test', engagement: 'lab')
      expect(offered.first[:secret]).to eq('hunter2')
    end
  end
end
