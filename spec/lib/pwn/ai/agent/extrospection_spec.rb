# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::Agent::Extrospection do
  it 'should display information for authors' do
    authors_response = PWN::AI::Agent::Extrospection
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::AI::Agent::Extrospection
    expect(help_response).to respond_to :help
  end

  it 'should expose rf_tune as a public RF sense organ' do
    expect(PWN::AI::Agent::Extrospection).to respond_to :rf_tune
  end

  it 'should expose osint / serial / telecomm / packet / vision / voice sense organs' do
    %i[osint serial_sense telecomm packet_sense vision voice_sense].each do |m|
      expect(PWN::AI::Agent::Extrospection).to respond_to m
    end
  end

  it 'should auto-detect OSINT kind for common query shapes' do
    det = ->(q) { PWN::AI::Agent::Extrospection.send(:detect_osint_kind, query: q) }
    expect(det.call('8.8.8.8')).to eq :ip
    expect(det.call('example.com')).to eq :domain
    expect(det.call('+13125551212')).to eq :phone
    expect(det.call('Jane Doe')).to eq :person
    expect(det.call('US10123456')).to eq :patent
    expect(det.call('2ABIP-ESP32')).to eq :fcc_id
    expect(det.call('someone@example.com')).to eq :email
    expect(det.call('https://evil.example/path')).to eq :url
    expect(det.call('Acme Robotics LLC')).to eq :company
    expect(det.call('0000320193')).to eq :cik
    expect(det.call('123 Main Street Springfield')).to eq :geo
    expect(det.call('birth record Jane Doe')).to eq :vital_records
  end

  it 'should route new public feeds through osint_dispatch' do
    feeds = %i[otx urlhaus threatfox urlscan hackertarget openfda nominatim opencorporates courtlistener sec_edgar vital_records]
    feeds.each do |f|
      # Dispatch should not raise — network failures become error hashes.
      res = PWN::AI::Agent::Extrospection.send(
        :osint_dispatch,
        feed: f,
        query: 'example.com',
        limit: 1,
        keys: {}
      )
      expect(res).to be_a(Hash)
    end
  end

  it 'should include expanded DEFAULT_OSINT_FEEDS' do
    feeds = PWN::AI::Agent::Extrospection.const_get(:DEFAULT_OSINT_FEEDS)
    %i[otx urlhaus threatfox urlscan openfda nominatim opencorporates courtlistener sec_edgar vital_records].each do |f|
      expect(feeds).to include(f)
    end
  end
end
