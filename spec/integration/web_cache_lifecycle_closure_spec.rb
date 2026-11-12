# frozen_string_literal: true

require 'spec_helper'
require 'uri'
require 'net/http'

RSpec.describe 'web cache CLI lifecycle closure' do
  include_context 'pwn tmp sandbox'

  let(:script) { File.expand_path('../../bin/pwn_web_cache_deception', __dir__) }
  let(:browser) { double('offline browser', goto: nil, html: '<html>fixture</html>') }
  let(:handle) { { browser: browser } }
  let(:password_field) { double('password field', set: nil) }
  let(:args) do
    ['--target-url=https://example.invalid/path#section', "--output-results=#{File.join(@tmp, 'results.txt')}",
     '--pwn-www-mod=GitHub', '--password=  synthetic password  ']
  end

  before do
    allow(Dir).to receive(:home).and_return(@tmp)
    stub_const('ARGV', args.dup)
    allow(PWN::Env).to receive(:[]).and_call_original
    allow(PWN::Env).to receive(:[]).with(:driver_opts).and_return({})
    allow(PWN::Config).to receive(:refresh_env)
    allow(PWN::Plugins::TransparentBrowser).to receive(:open).and_return(handle)
    allow(PWN::Plugins::TransparentBrowser).to receive(:close).and_return(nil)
    allow(PWN::Plugins::AuthenticationHelper).to receive(:mask_password).and_raise('unexpected credential prompt')
    allow(password_field).to receive(:wait_until).and_return(password_field)
    username = double('username field', set: nil)
    allow(username).to receive(:wait_until).and_return(username)
    button = double('submit button', exist?: true, click!: nil)
    allow(button).to receive(:wait_until).and_return(button)
    allow(browser).to receive(:text_field).with(name: 'login').and_return(username)
    allow(browser).to receive(:text_field).with(name: 'password').and_return(password_field)
    allow(browser).to receive(:input).with(name: 'commit').and_return(button)
  end

  %w[target-url output-results].each do |flag|
    it "R09 rejects missing #{flag} before opening or prompting" do
      ARGV.reject! { |arg| arg.start_with?("--#{flag}=", '--password=') }
      expect { load script, true }.to raise_error(ArgumentError, /required/i)
      expect(PWN::Plugins::TransparentBrowser).not_to have_received(:open)
      expect(PWN::Plugins::AuthenticationHelper).not_to have_received(:mask_password)
    end
  end

  ['file:///etc/passwd', '/relative', 'https:///missing-host', 'ftp://example.invalid'].each do |url|
    it "R09 rejects unsupported URL #{url} before opening" do
      ARGV[0] = "--target-url=#{url}"
      expect { load script, true }.to raise_error(ArgumentError, /URL/)
      expect(PWN::Plugins::TransparentBrowser).not_to have_received(:open)
    end
  end

  it 'R09 validates the authentication adapter before requesting a password' do
    ARGV.reject! { |arg| arg.start_with?('--password=') }
    ARGV.map! { |arg| arg == '--pwn-www-mod=GitHub' ? '--pwn-www-mod=MissingFixtureAdapter' : arg }
    expect { load script, true }.to raise_error(ArgumentError, /Invalid module/)
    expect(PWN::Plugins::AuthenticationHelper).not_to have_received(:mask_password)
    expect(PWN::Plugins::TransparentBrowser).not_to have_received(:open)
  end

  it 'R09 rejects an unusable output parent before prompting or opening' do
    ARGV[1] = "--output-results=#{File.join(@tmp, 'absent', 'results')}"
    ARGV.reject! { |arg| arg.start_with?('--password=') }
    expect { load script, true }.to raise_error(ArgumentError, /output/)
    expect(PWN::Plugins::TransparentBrowser).not_to have_received(:open)
    expect(PWN::Plugins::AuthenticationHelper).not_to have_received(:mask_password)
  end

  it 'R08 closes its opened handle even when real adapter login and logout both fail' do
    allow(browser).to receive(:goto).with('https://github.com/login').and_raise(IOError, 'primary login failure')
    allow(browser).to receive(:goto).with('https://github.com/logout').and_raise(IOError, 'secondary logout failure')
    expect { load script, true }.to raise_error(IOError, 'primary login failure')
    expect(PWN::Plugins::TransparentBrowser).to have_received(:close).with(browser_obj: handle)
  end

  it 'R08 closes its original handle when login returns nil' do
    allow(PWN::WWW::GitHub).to receive(:login).and_return(nil)
    expect { load script, true }.to raise_error(NoMethodError)
    expect(PWN::Plugins::TransparentBrowser).to have_received(:close).with(browser_obj: handle)
  end

  it 'R07 preserves explicit password characters through the actual GitHub adapter' do
    load script, true
    expect(password_field).to have_received(:set).with('  synthetic password  ')
    expect(browser).to have_received(:goto).with('https://example.invalid/path/wcd.aif#section')
  end
end
