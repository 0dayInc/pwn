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
    expect(det.call('1HGCM82633A004352')).to eq :vin
    expect(det.call('00:11:22:33:44:55')).to eq :mac
    expect(det.call('W1AW')).to eq :callsign
    expect(det.call('CVE-2021-44228')).to eq :cve
    expect(det.call('NPI 1679576722')).to eq :npi
  end

  it 'should route new public feeds through osint_dispatch' do
    feeds = %i[
      otx urlhaus threatfox urlscan hackertarget openfda nominatim
      opencorporates courtlistener sec_edgar vital_records
      ipapi_is iplocate ipwhois abuseipdb virustotal greynoise
      certspotter epss cisa_kev nhtsa nppes federal_register
      uk_police callook mac_vendor universities microlink
      agify genderize nationalize haveibeenpwned securitytrails
    ]
    feeds.each do |f|
      # Dispatch should not raise — network failures become error hashes.
      query = case f
              when :epss, :cisa_kev then 'CVE-2021-44228'
              when :nhtsa then '1HGCM82633A004352'
              when :mac_vendor then '00:11:22:33:44:55'
              when :callook then 'W1AW'
              when :nppes then 'John Smith'
              when :agify, :genderize, :nationalize then 'Michael'
              when :uk_police then 'metropolitan'
              else 'example.com'
              end
      res = PWN::AI::Agent::Extrospection.send(
        :osint_dispatch,
        feed: f,
        query: query,
        limit: 1,
        keys: {}
      )
      expect(res).to be_a(Hash)
    end
  end

  it 'should include expanded DEFAULT_OSINT_FEEDS' do
    feeds = PWN::AI::Agent::Extrospection.const_get(:DEFAULT_OSINT_FEEDS)
    %i[
      otx urlhaus threatfox urlscan openfda nominatim opencorporates
      courtlistener sec_edgar vital_records
      ipapi_is iplocate ipwhois abuseipdb virustotal greynoise
      certspotter epss cisa_kev nhtsa nppes federal_register
      uk_police callook mac_vendor universities microlink
      agify genderize nationalize haveibeenpwned securitytrails
    ].each do |f|
      expect(feeds).to include(f)
    end
  end

  it 'should skip keyed public-api-lists feeds when no API key is present' do
    %i[abuseipdb virustotal haveibeenpwned securitytrails].each do |f|
      res = PWN::AI::Agent::Extrospection.send(
        :osint_dispatch, feed: f, query: '8.8.8.8', limit: 1, keys: {}
      )
      expect(res).to be_a(Hash)
      expect(res[:skipped]).to eq(true)
    end
  end

  it 'should select public-api-lists-aware feeds per kind' do
    ip_feeds = PWN::AI::Agent::Extrospection.send(:osint_feeds_for, kind: :ip)
    expect(ip_feeds).to include(:ipapi_is, :iplocate, :abuseipdb, :greynoise)
    cve_feeds = PWN::AI::Agent::Extrospection.send(:osint_feeds_for, kind: :cve)
    expect(cve_feeds).to include(:epss, :cisa_kev)
    vin_feeds = PWN::AI::Agent::Extrospection.send(:osint_feeds_for, kind: :vin)
    expect(vin_feeds).to eq(%i[nhtsa])
  end
end
