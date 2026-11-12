# frozen_string_literal: true

require 'spec_helper'

RSpec.describe PWN::Plugins::NexposeVulnScan do
  let(:client) { double('nexpose') }
  let(:logger) { described_class.class_variable_get(:@@logger) }

  before do
    allow(client).to receive(:list_sites).and_return([double('site', name: 'fixture', id: 7)])
    allow(client).to receive(:scan_site).with(7).and_return(41)
    allow(logger).to receive(:info)
  end

  it '[PBR-05] does not call an aborted activity row completed' do
    allow(client).to receive(:scan_activity).and_return([double('scan', site_id: 7, status: 'aborted')])
    expect(described_class.scan_site_by_name(nsc_obj: client, site_name: 'fixture', poll_interval: 0)).to be_nil
    expect(logger).not_to have_received(:info).with(/Completed/)
  end

  it '[PBR-05] polls the launched site through active states to explicit success' do
    foreign = double('foreign', site_id: 7, scan_id: 40, status: 'finished')
    allow(client).to receive(:scan_activity).and_return(
      [foreign, double('scan', site_id: 7, scan_id: 41, status: 'dispatched')],
      [foreign, double('scan', site_id: 7, scan_id: 41, status: 'paused')],
      [foreign, double('scan', site_id: 7, scan_id: 41, status: 'integrating')],
      [foreign, double('scan', site_id: 7, scan_id: 41, status: 'finished')]
    )
    expect(described_class.scan_site_by_name(nsc_obj: client, site_name: 'fixture', poll_interval: 0)).to equal(client)
  end

  it '[PBR-05] bounds persistent active states and reports unknown, not success' do
    allow(client).to receive(:scan_activity).and_return([double('scan', site_id: 7, scan_id: 41, status: 'running')])
    expect { described_class.scan_site_by_name(nsc_obj: client, site_name: 'fixture', poll_interval: 0, max_polls: 2) }.to raise_error(IOError, /unknown.*poll limit/)
  end

  it '[PBR-05] bounds a blocked activity request' do
    allow(client).to receive(:scan_activity) { sleep 1 }
    expect { described_class.scan_site_by_name(nsc_obj: client, site_name: 'fixture', timeout: 0.01) }.to raise_error(IOError, /unknown.*deadline/)
  end

  [nil, 'unknown', 'SYNTHETIC-PRIVATE-STATUS'].each do |status|
    it "[PBR-05] treats #{status.inspect} status as incomplete without echoing it" do
      allow(client).to receive(:scan_activity).and_return([double('scan', site_id: 7, scan_id: 41, status: status)])
      expect(described_class.scan_site_by_name(nsc_obj: client, site_name: 'fixture', poll_interval: 0)).to be_nil
      expect(logger).not_to have_received(:info).with(/SYNTHETIC-PRIVATE-STATUS|Completed/)
    end
  end

  it '[PBR-05] refuses a missing launch identity rather than polling unrelated activity' do
    allow(client).to receive(:scan_site).and_return(nil)
    expect(client).not_to receive(:scan_activity)
    expect { described_class.scan_site_by_name(nsc_obj: client, site_name: 'fixture') }.to raise_error(IOError, /unknown.*identity/)
  end
end
