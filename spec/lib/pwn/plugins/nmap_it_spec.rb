# frozen_string_literal: true

require 'spec_helper'

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
end
