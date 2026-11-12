# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'pwn_web_cache_deception lifecycle audit' do
  let(:script) { File.expand_path('../../bin/pwn_web_cache_deception', __dir__) }
  let(:browser) { double('offline browser', goto: nil, html: '<html>fixture</html>') }
  let(:browser_obj) { { browser: browser } }
  let(:provider) { double('offline WWW provider', open: browser_obj, login: browser_obj, logout: browser_obj, close: nil) }
  let(:driver_opts) { {} }
  let(:args) do
    ['--target-url=https://example.invalid/path', "--output-results=#{File.join(@directory, 'results.txt')}",
     '--pwn-www-mod=GitHub', '-pfixture-password']
  end

  around do |example|
    Dir.mktmpdir('pwn-wcd-audit-') do |directory|
      @directory = directory
      example.run
    end
  end

  before do
    stub_const('ARGV', args.dup)
    allow(PWN::Env).to receive(:[]).and_call_original
    allow(PWN::Env).to receive(:[]).with(:driver_opts).and_return(driver_opts)
    allow(PWN::Config).to receive(:refresh_env)
    stub_const('PWN::WWW::GitHub', provider)
    stub_const('PWN::Plugins::TransparentBrowser', double('offline browser boundary', open: browser_obj, close: nil))
    allow(PWN::Plugins::AuthenticationHelper).to receive(:mask_password).and_raise('unexpected password prompt')
  end

  it 'does not request a password for unauthenticated scans' do
    ARGV.reject! { |arg| arg.start_with?('--pwn-www-mod=', '-pfixture') }
    expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
    load script, true
    expect(File.read(File.join(@directory, 'results.txt'))).to include('Potential Candidate')
  end

  it 'reports an invalid authentication module rather than resolving NAME_ERROR' do
    ARGV.map! { |arg| arg == '--pwn-www-mod=GitHub' ? '--pwn-www-mod=MissingFixtureModule' : arg }
    expect { load script, true }.to raise_error(ArgumentError, /Invalid module/)
  end

  it 'reports an invalid authentication module without a secondary NameError or browser close' do
    ARGV.map! { |arg| arg == '--pwn-www-mod=GitHub' ? '--pwn-www-mod=MissingFixtureModule' : arg }
    expect(PWN::Plugins::TransparentBrowser).not_to receive(:close)
    expect { load script, true }.to raise_error(ArgumentError, /Invalid module/)
  end

  it 'rejects an authentication adapter without a close operation before opening it' do
    incomplete = double('incomplete adapter', open: browser_obj, login: browser_obj, logout: browser_obj)
    stub_const('PWN::WWW::GitHub', incomplete)
    expect(incomplete).not_to receive(:open)
    expect { load script, true }.to raise_error(ArgumentError, /close/)
  end

  it 'appends the payload to the URL path rather than its fragment' do
    ARGV.map! { |arg| arg.start_with?('--target-url=') ? '--target-url=https://example.invalid/path#section' : arg }
    load script, true
    expect(browser).to have_received(:goto).with('https://example.invalid/path/wcd.aif#section')
    expect(browser).not_to have_received(:goto).with('https://example.invalid/path#section/wcd.aif')
  end

  it 'parses the advertised short password option without treating it as a proxy' do
    expect(provider).to receive(:login).with(hash_including(password: 'fixture-password')).and_return(browser_obj)
    expect(provider).to receive(:open).with(browser_type: :chrome).and_return(browser_obj)
    load script, true
  end
end
