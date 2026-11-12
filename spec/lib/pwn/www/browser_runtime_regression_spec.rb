# frozen_string_literal: true

require 'spec_helper'
require 'watir'

RSpec.describe 'WWW browser runtime regressions' do
  let(:browser) { instance_double(Watir::Browser) }
  let(:handle) { { browser: browser, type: :firefox } }
  let(:field) { instance_double(Watir::TextField, set: nil, send_keys: nil) }
  let(:button) { instance_double(Watir::Button, click!: nil, click: nil) }
  let(:element) { instance_double(Watir::HTMLElement, click!: nil, click: nil, hover: nil) }

  before do
    allow(field).to receive(:wait_until).and_return(field)
    allow(button).to receive(:wait_until).and_return(button)
    allow(element).to receive(:wait_until).and_return(element)
    allow(browser).to receive_messages(goto: nil, text_field: field, button: button, input: button, span: element, div: element, li: element, link: element, img: element, i: element)
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(handle)
    allow(PWN::Plugins::TransparentBrowser).to receive(:close).and_return(nil)
  end

  destinations = {
    AppCobaltIO: 'https://app.cobalt.io', Bing: 'https://www.bing.com', BugCrowd: 'https://bugcrowd.com',
    Checkip: 'http://checkip.amazonaws.com', CoinbasePro: 'https://pro.coinbase.com', Duckduckgo: 'https://duckduckgo.com',
    Facebook: 'https://www.facebook.com', GitHub: 'https://github.com', Google: 'https://www.google.com',
    HackerOne: 'https://www.hackerone.com', Linkedin: 'https://www.linkedin.com', Pandora: 'https://www.pandora.com',
    Pastebin: 'https://pastebin.com', Paypal: 'https://www.paypal.com', Synack: 'https://www.synack.com',
    Torch: 'http://www.torchtorsearch.com', TradingView: 'https://tradingview.com', Twitter: 'https://twitter.com',
    Uber: 'https://www.uber.com', Upwork: 'https://www.upwork.com', WaybackMachine: 'https://web.archive.org', Youtube: 'https://www.youtube.com'
  }
  destinations.each do |name, destination|
    it "opens #{name} through the browser transport and returns its handle" do
      allow(browser).to receive(:html).and_return('<pre>192.0.2.1</pre>')
      options = { browser_type: :firefox, proxy: 'http://fixture.invalid:8080' }
      expect(PWN::Plugins::TransparentBrowser).to receive(:open).with(options).and_return(handle)
      expect(browser).to receive(:goto).with(destination)
      expect(PWN::WWW.const_get(name).open(options)).to equal(handle)
    end

    it "closes the newly opened #{name} transport when initial navigation fails" do
      error = IOError.new('fixture navigation failure')
      allow(browser).to receive(:goto).and_raise(error)
      expect(PWN::Plugins::TransparentBrowser).to receive(:close).with(browser_obj: handle)
      expect { PWN::WWW.const_get(name).open(browser_type: :firefox) }.to(raise_error { |actual| expect(actual).to equal(error) })
    end

    it "closes #{name} through the browser transport" do
      expect(PWN::Plugins::TransparentBrowser).to receive(:close).with(browser_obj: handle).and_return(nil)
      expect(PWN::WWW.const_get(name).close(browser_obj: handle)).to be_nil
    end
  end

  passwords = {
    AppCobaltIO: { index: 10 }, BugCrowd: { id: 'user_password' }, CoinbasePro: { name: 'password' },
    Facebook: { id: 'pass' }, GitHub: { name: 'password' }, HackerOne: { name: 'user[password]' },
    Linkedin: { name: 'session_password' }, Pandora: { id: 'login_password' }, Paypal: { id: 'password' },
    Synack: { name: 'password' }, TradingView: { name: 'password' }, Twitter: { index: 3 },
    Uber: { id: 'password' }, Upwork: { id: 'login_password' }
  }
  passwords.each do |name, selector|
    it "preserves the exact supplied password in #{name} login" do
      password = " \tfixture-only password \n"
      password_field = instance_double(Watir::TextField)
      allow(password_field).to receive(:wait_until).and_return(password_field)
      expect(browser).to receive(:text_field).with(selector).and_return(password_field)
      expect(password_field).to receive(:set).with(password)
      expect(PWN::WWW.const_get(name).login(browser_obj: handle, username: 'fixture@example.invalid', password: password)).to equal(handle)
    end
  end

  %i[Bing Duckduckgo Google Torch Youtube].each do |name|
    it "submits #{name} search using the open browser" do
      allow(browser).to receive(:url).and_return('https://duckduckgo.com/')
      expect(field).to receive(:set).with('fixture query')
      expect(button).to receive(:click!)
      expect(PWN::WWW.const_get(name).search(browser_obj: handle, q: 'fixture query')).to equal(handle)
    end
  end

  it 'preserves both password fields during simulated PayPal signup' do
    password = ' fixture-only password '
    select = instance_double(Watir::Select)
    allow(select).to receive(:wait_until).and_return(select)
    allow(browser).to receive(:select).and_return(select)
    expect(select).to receive(:select).with(value: 'AZ')
    expect(field).to receive(:set).with(password).twice
    expect(PWN::WWW::Paypal.signup(browser_obj: handle, password: password, state: 'AZ')).to equal(handle)
  end

  it 'submits Wayback search using a supported Watir element action' do
    expect(field).to receive(:set).with('fixture query').and_return(nil)
    expect(field).to receive(:send_keys).with(:enter)
    expect(PWN::WWW::WaybackMachine.search(browser_obj: handle, q: 'fixture query')).to equal(handle)
  end

  it 'accepts the documented browser options for Torch onion navigation' do
    expect(browser).to receive(:goto).with('http://xmh57jrzrnw6insl.onion')
    expect(PWN::WWW::Torch.onion(browser_obj: handle)).to equal(handle)
  end
end
