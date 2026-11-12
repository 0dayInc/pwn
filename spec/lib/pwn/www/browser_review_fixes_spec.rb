# frozen_string_literal: true

require 'spec_helper'
require 'watir'

RSpec.describe 'WWW real browser-helper review contracts' do
  before do
    @driver = Selenium::WebDriver::Driver.allocate
    @navigation = instance_double(Selenium::WebDriver::Navigation, to: nil)
    timeouts = instance_double(Selenium::WebDriver::Timeouts, 'page_load=': nil, 'script=': nil)
    management = instance_double(Selenium::WebDriver::Manager, timeouts: timeouts)
    allow(@driver).to receive_messages(navigate: @navigation, quit: nil, manage: management, page_source: '<pre>192.0.2.1</pre>')
    allow(Selenium::WebDriver).to receive(:for).and_return(@driver)
  end

  names = %i[AppCobaltIO Bing BugCrowd Checkip CoinbasePro Duckduckgo Facebook GitHub Google HackerOne
             Linkedin Pandora Pastebin Paypal Synack Torch TradingView Twitter Uber Upwork WaybackMachine Youtube].freeze

  it 'covers every WWW wrapper rather than an incidental subset' do
    expect(PWN::WWW.constants(false).sort).to eq(names.sort)
    expect(Dir[File.expand_path('../../../../lib/pwn/www/*.rb', __dir__)].length).to eq(names.length)
  end

  names.each do |name|
    it "SERVICES-REVIEW-006 preserves #{name} navigation error when driver quit fails" do
      original = IOError.new('fixture navigation failure')
      allow(@navigation).to receive(:to).and_raise(original)
      expect(@driver).to receive(:quit).once.and_raise(RuntimeError, 'fixture driver cleanup failure')

      expect { PWN::WWW.const_get(name).open({}.freeze) }.to(raise_error { |error| expect(error).to equal(original) })
    end

    it "SERVICES-REVIEW-006 still closes #{name} browser if its owned Tor cleanup fails" do
      original = IOError.new('fixture navigation failure')
      allow(@navigation).to receive(:to).and_raise(original)
      tor = { ip: '127.0.0.1', port: 1 }
      allow(PWN::Plugins::Tor).to receive(:start).and_return(tor)
      expect(PWN::Plugins::Tor).to receive(:stop).with(tor_obj: tor).once.and_raise(RuntimeError, 'fixture Tor cleanup failure')
      expect(@driver).to receive(:quit).once

      expect { PWN::WWW.const_get(name).open(proxy: 'tor') }.to(raise_error { |error| expect(error).to equal(original) })
    end

    [false, true].each do |frozen|
      it "SERVICES-REVIEW-004 preserves #{frozen ? 'frozen' : 'mutable'} caller options through real #{name} and Watir" do
        options = {}
        options.freeze if frozen
        handle = PWN::WWW.const_get(name).open(options)

        expect(handle[:browser]).to be_a(Watir::Browser)
        expect(handle[:browser].driver).to equal(@driver)
        expect(options).to eq({})
      ensure
        PWN::WWW.const_get(name).close(browser_obj: handle) if handle
      end
    end

    it "SERVICES-REVIEW-004 preserves explicit false and nested options through real #{name}" do
      capture_proxy = { url: 'http://fixture.invalid:8080', metadata: ['synthetic'].freeze }.freeze
      options = { browser_type: :chrome, devtools: false, capture_proxy: capture_proxy }.freeze
      original = Marshal.dump(options)
      handle = PWN::WWW.const_get(name).open(options)

      expect(Marshal.dump(options)).to eq(original)
      expect(handle[:capture_proxy]).to equal(capture_proxy)
    ensure
      PWN::WWW.const_get(name).close(browser_obj: handle) if handle
    end
  end
end
