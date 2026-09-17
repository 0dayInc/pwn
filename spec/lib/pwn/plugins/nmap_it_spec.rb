# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'fileutils'

describe PWN::Plugins::NmapIt do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::NmapIt
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::NmapIt
    expect(help_response).to respond_to :help
  end

  it 'port_scan accepts opts = {} and aliases xml to output_xml' do
    expect(described_class.method(:port_scan).parameters).to include(%i[opt opts])
    src = File.read(described_class.method(:port_scan).source_location.first)
    expect(src).to include('opts[')
    expect(src).to include('output_xml')
  end

  it 'to_findings returns [] for a missing xml file' do
    expect(described_class.to_findings(xml_file: '/tmp/no-such-nmap.xml')).to eq([])
  end

  def write_nmap_xml(path, hosts)
    body = +'<?xml version="1.0"?><nmaprun>'
    hosts.each do |host|
      body << %(<host><status state="up"/><address addr="#{host[:ip]}" addrtype="ipv4"/>)
      body << '<ports>'
      Array(host[:ports]).each do |port|
        body << %(<port protocol="#{port[:proto] || 'tcp'}" portid="#{port[:id]}"><state state="#{port[:state] || 'open'}"/><service name="#{port[:service]}" version="#{port[:version]}"/>)
        Array(port[:scripts]).each do |name, output|
          body << %(<script id="#{name}" output="#{output}"/>)
        end
        body << '</port>'
      end
      body << '</ports>'
      if host[:scripts]
        body << '<hostscript>'
        host[:scripts].each { |name, output| body << %(<script id="#{name}" output="#{output}"/>) }
        body << '</hostscript>'
      end
      body << '</host>'
    end
    body << '</nmaprun>'
    File.write(path, body)
  end

  it 'ingests XML into the engagement store and answers what changed since yesterday in one query' do
    Dir.mktmpdir('pwn-nmap-store-') do |dir|
      stub_const('PWN::AI::Agent::Engagement::ROOT', dir)
      stub_const('PWN::AI::Agent::Engagement::ACTIVE_FILE', File.join(dir, 'active'))
      PWN::Engagement.open(name: 'lab', scope_cidrs: ['10.0.0.0/8'])
      yesterday = File.join(dir, 'yesterday.xml')
      today = File.join(dir, 'today.xml')
      write_nmap_xml(yesterday, [{ ip: '10.0.0.1', ports: [{ id: 22, service: 'ssh', version: 'OpenSSH' }], scripts: { 'smb-os-discovery' => 'Windows' } }])
      write_nmap_xml(today, [{ ip: '10.0.0.1', ports: [{ id: 22, service: 'ssh', version: 'OpenSSH' }, { id: 80, service: 'http', scripts: { 'http-title' => 'Admin' } }] }])
      first = described_class.scan(xml: yesterday, engagement: 'lab', override: true, at: Time.now.utc - (26 * 3600))
      expect(first[:hosts].first[:host]).to eq('10.0.0.1')
      expect(first[:hosts].first[:scripts].to_s).to include('smb-os-discovery')
      stored = PWN::Engagement.hosts(name: 'lab')
      expect(stored.values.first[:services]).to include('ssh')
      second = described_class.scan(xml: today, engagement: 'lab', override: true, at: Time.now.utc)
      expect(second[:diff][:added_ports].map { |row| row[:port] }).to include(80)
      delta = described_class.changes(since: 'yesterday', engagement: 'lab')
      expect(delta[:added_ports].map { |row| row[:port] }).to include(80)
      expect(delta[:added_ports].map { |row| row[:port] }).not_to include(22)
      expect(delta[:changed_scripts].any? { |row| row[:name].to_s.include?('http-title') || row[:after].to_s.include?('Admin') }).to eq(true)
    end
  end
end
