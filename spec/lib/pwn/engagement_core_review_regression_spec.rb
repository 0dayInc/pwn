# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'PWN::Engagement core review regressions' do
  include_context 'pwn tmp sandbox'

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    stub_const('PWN::AI::Agent::Engagement::ROOT', File.join(@tmp, 'engagements'))
    stub_const('PWN::AI::Agent::Engagement::ACTIVE_FILE', File.join(@tmp, 'engagements', 'active'))
  end

  describe 'E2 enumerates literal engagement scan directories' do
    it 'does not use missing wildcard names to enumerate other engagements' do
      PWN::Engagement.record_scan(name: 'other', hosts: [{ host: '192.0.2.2' }], at: Time.utc(2026, 1, 1))
      expect(PWN::Engagement.scans(name: '*')).to be_empty
      expect(PWN::Engagement.scans(name: '?ther')).to be_empty
      expect(PWN::Engagement.scans(name: '{other,absent}')).to be_empty
    end

    it 'round trips bracket and wildcard components without changing their spelling', :aggregate_failures do
      PWN::Engagement.record_scan(name: 'other', hosts: [{ host: '192.0.2.2' }], at: Time.utc(2026, 1, 1))
      ['fixture[1]', '*', '?', '{other,fixture}'].each do |name|
        later = PWN::Engagement.record_scan(name: name, hosts: [{ host: '192.0.2.1' }], at: Time.utc(2026, 1, 2))
        earlier = PWN::Engagement.record_scan(name: name, hosts: [], at: Time.utc(2026, 1, 1))
        expect(PWN::Engagement.scans(name: name)).to eq([earlier, later]), name
      end
    end
  end

  describe 'E1 separates storage fallback from scope selection' do
    it 'persists the real no-active Nmap XML import in default host storage' do
      xml = File.join(@tmp, 'inventory.xml')
      File.write(xml, '<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>')
      expect(PWN::AI::Agent::Engagement.current_name).to be_nil
      expect(PWN::Engagement.in_scope?(host: '192.0.2.1')).to be(true)
      expect(PWN::Plugins::NmapIt).not_to receive(:port_scan)
      result = PWN::Plugins::NmapIt.scan(targets: ['192.0.2.1'], xml_file: xml)
      expect(result[:hosts].first[:host]).to eq('192.0.2.1')
      expect(PWN::Engagement.hosts[:'192.0.2.1']).to include(host: '192.0.2.1', services: ['https'])
      path = File.join(PWN::AI::Agent::Engagement::ROOT, 'default', 'hosts.json')
      expect(JSON.parse(File.read(path)).keys).to eq(['192.0.2.1'])
      expect(PWN::Engagement.scans.length).to eq(1)
    end

    it 'does not silently activate a stored default scope after it is closed' do
      PWN::Engagement.open(name: 'default', scope_domains: ['default.invalid'])
      PWN::Engagement.close
      expect(PWN::Engagement.record_host(host: '192.0.2.1')).to include(host: '192.0.2.1')
      expect(PWN::Engagement.record_host(name: 'default', host: '192.0.2.2')).to include(ok: false, recorded: false)
      expect(PWN::Engagement.hosts.keys).to eq([:'192.0.2.1'])
    end

    it 'still rejects explicitly missing and dangling-active engagements' do
      %i[name engagement].each do |key|
        expect(PWN::Engagement.record_host(key => 'default', :host => '192.0.2.1')).to include(ok: false, recorded: false)
      end
      FileUtils.mkdir_p(PWN::AI::Agent::Engagement::ROOT)
      File.write(PWN::AI::Agent::Engagement::ACTIVE_FILE, 'missing')
      expect(PWN::Engagement.record_host(host: '192.0.2.1')).to include(ok: false, recorded: false)
      expect(File).not_to exist(File.join(PWN::AI::Agent::Engagement::ROOT, 'default'))
      expect(File).not_to exist(File.join(PWN::AI::Agent::Engagement::ROOT, 'missing'))
    end

    it 'preserves active scope and literal override without alias bypasses' do
      PWN::Engagement.open(name: 'selected', scope_domains: ['selected.invalid'])
      PWN::Engagement.open(name: 'active-scope', scope_domains: ['active.invalid'])
      expect(PWN::Engagement.record_host(host: 'selected.invalid')).to include(ok: false, recorded: false)
      expect(PWN::Engagement.record_host(name: 'selected', engagement: 'selected', host: 'active.invalid')).to include(ok: false, recorded: false)
      expect(PWN::Engagement.record_host(name: 'selected', host: 'active.invalid', override: 'true')).to include(ok: false, recorded: false)
      expect(PWN::Engagement.record_host(engagement: 'selected', host: 'selected.invalid')).to include(host: 'selected.invalid')
      expect(PWN::Engagement.record_host(name: 'selected', host: 'active.invalid', override: true)).to include(host: 'active.invalid')
      expect(PWN::Engagement.hosts(name: 'active-scope')).to be_empty
    end

    it 'rejects conflicting aliases before host or scan storage operations', :aggregate_failures do
      PWN::Engagement.open(name: 'selected', scope_domains: ['selected.invalid'])
      PWN::Engagement.open(name: 'other', scope_domains: ['other.invalid'])
      opts = { name: 'other', engagement: 'selected', host: 'selected.invalid', hosts: [{ host: 'selected.invalid', port: 443 }] }
      %i[record_host merge_scan record_scan hosts scans].each do |method|
        expect { PWN::Engagement.public_send(method, opts) }.to raise_error(ArgumentError, /conflicting engagement/i), method.to_s
      end
      expect(PWN::Engagement.hosts(name: 'selected')).to be_empty
      expect(PWN::Engagement.scans(name: 'selected')).to be_empty
    end
  end
end
