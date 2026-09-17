# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'json'

describe PWN::Plugins::TransparentBrowser do
  it 'should display information for authors' do
    authors_response = PWN::Plugins::TransparentBrowser
    expect(authors_response).to respond_to :authors
  end

  it 'should display information for existing help method' do
    help_response = PWN::Plugins::TransparentBrowser
    expect(help_response).to respond_to :help
  end

  it 'hooks a capture proxy descriptor into browser transport' do
    require 'pwn/plugins/mitm_proxy'
    Dir.mktmpdir do |dir|
      proxy = PWN::Plugins::MitmProxy.start(har_path: File.join(dir, 'browser.har'))
      original = RestClient.proxy
      browser = described_class.open(browser_type: :rest, capture_proxy: proxy)
      expect(RestClient.proxy).to eq(proxy[:url])
      expect(browser[:capture_proxy]).to eq(proxy)
    ensure
      RestClient.proxy = original
      PWN::Plugins::MitmProxy.stop(proxy: proxy) if proxy
    end
  end

  it 'routes Chrome loopback traffic through the capture proxy instead of bypassing it' do
    proxy = { id: 'fixture', url: 'http://127.0.0.1:8888' }
    driver = double('driver')
    allow(Watir::Browser).to receive(:new).with(driver).and_return(Object.new)
    %i[chrome headless_chrome].each do |type|
      expect(Selenium::WebDriver).to receive(:for) do |engine, options:|
        expect(engine).to eq(:chrome)
        expect(options.args).to include('--proxy-server=http://127.0.0.1:8888', '--proxy-bypass-list=<-loopback>')
        driver
      end
      described_class.open(browser_type: type, capture_proxy: proxy)
    end
  end

  it 'caps Watir element waits and Selenium page_load / script timeouts' do
    src = File.read(described_class.method(:open).source_location.first)
    expect(src).to match(/Watir\.default_timeout\s*=\s*15/)
    expect(src).not_to match(/Watir\.default_timeout\s*=\s*900/)
    expect(src).to match(/page_load\s*=\s*45/)
    expect(src).to match(/script\s*=\s*30/)
  end

  it 'evidence! writes screenshot, dom, and har files' do
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
      browser = Object.new
      def browser.html
        '<html/>'
      end
      out = described_class.evidence!(browser_obj: { browser: browser }, label: 't', session_id: 's')
      expect(File.file?(out[:screenshot])).to be true
      expect(File.file?(out[:dom])).to be true
      expect(File.file?(out[:har])).to be true
    end
  end

  it 'goto optionally spills screenshot, DOM, and HAR into the artifact store' do
    Dir.mktmpdir('pwn-tb-cap-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
      browser = Object.new
      def browser.html
        '<html><body>admin</body></html>'
      end

      def browser.goto(url)
        @url = url
      end

      def browser.url
        @url.to_s
      end
      out = described_class.goto(
        browser_obj: { browser: browser },
        url: 'https://app.example.test/admin',
        capture: true,
        session_id: 'web'
      )
      expect(out[:url]).to include('/admin')
      expect(File.binread(out[:evidence][:screenshot]).b.start_with?("\x89PNG".b)).to be true
      har = JSON.parse(File.read(out[:evidence][:har]))
      expect(har.dig('log', 'entries').to_s).to include('/admin')
      expect(out[:evidence][:screenshot_handle].to_s).not_to be_empty
      expect(out[:evidence][:har_handle].to_s).not_to be_empty
    end
  end

  it 'records an auth-bypass finding with pixel and HAR proof in one goto' do
    Dir.mktmpdir('pwn-tb-find-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
      stub_const('PWN::Plugins::Findings::FILE', File.join(dir, 'findings.jsonl'))
      browser = Object.new
      def browser.html
        '<html><h1>Dashboard</h1></html>'
      end

      def browser.goto(url)
        @url = url
      end

      def browser.url
        @url.to_s
      end
      out = described_class.goto(
        browser_obj: { browser: browser },
        url: 'https://app.example.test/admin',
        title: 'Auth bypass',
        severity: 'high',
        session_id: 'web'
      )
      row = out[:finding]
      expect(row[:title]).to match(/auth bypass/i)
      arts = Array(row[:poc_artifacts]) + Array(row[:evidence_artifacts]).flat_map { |item| [item[:path], item[:stored]] }
      shot = arts.find { |path| path.to_s.end_with?('.png') || (File.file?(path.to_s) && File.binread(path).b.start_with?("\x89PNG".b)) }
      har = arts.find { |path| path.to_s.include?('har') || (File.file?(path.to_s) && File.read(path).include?('"log"')) }
      expect(shot).not_to be_nil
      expect(har).not_to be_nil
      expect(File.binread(shot).b.start_with?("\x89PNG".b)).to be true
      expect(JSON.parse(File.read(har)).dig('log', 'entries').to_s).to include('/admin')
      stored = PWN::Plugins::Findings.report
      expect(stored.first[:title]).to match(/auth bypass/i)
    end
  end
end
