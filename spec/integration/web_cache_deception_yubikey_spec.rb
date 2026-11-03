# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'pwn_web_cache_deception YubiKey options' do
  let(:script) { File.expand_path('../../bin/pwn_web_cache_deception', __dir__) }
  let(:browser) { double('offline browser', goto: nil, html: '<html>offline</html>') }
  let(:browser_obj) { { browser: browser } }
  let(:provider) { double('offline WWW provider', open: browser_obj, login: browser_obj, logout: browser_obj, close: nil) }
  let(:driver_opts) { {} }
  let(:account) { 'Example:tester@example.invalid' }
  let(:serial) { '00123456' }
  let(:args) do
    ['--target-url=https://example.invalid/test', "--output-results=#{File.join(@tmpdir, 'results.txt')}",
     '--pwn-www-mod=GitHub', '--username=tester@example.invalid', '--password=fake-password',
     "--yubikey-account=#{account}", '--yubikey-confirm', "--yubikey-serial=#{serial}", '--no-mfa']
  end

  around do |example|
    Dir.mktmpdir('pwn-wcd-yubikey-') do |dir|
      @tmpdir = dir
      example.run
    end
  end

  before do
    stub_const('ARGV', args.dup)
    allow(PWN::Env).to receive(:[]).and_call_original
    allow(PWN::Env).to receive(:[]).with(:driver_opts).and_return(driver_opts)
    allow(PWN::Config).to receive(:refresh_env)
    stub_const('PWN::WWW::GitHub', provider)
    stub_const('PWN::Plugins::YubiKey', double('offline device boundary'))
    stub_const('PWN::Plugins::TransparentBrowser', double('offline browser boundary', close: nil))
    allow(PWN::Plugins::AuthenticationHelper).to receive(:mask_password).and_raise('unexpected password prompt')
  end

  it 'forwards exact account and serial options to GitHub login even with --no-mfa' do
    expected = { browser_obj: browser_obj, username: 'tester@example.invalid', password: 'fake-password', mfa: false, yubikey: { account: account, confirm: true, serial: serial } }
    expect(provider).to receive(:login).with(expected).and_return(browser_obj)
    expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
    load script, true
  end

  %w[Synack Twitter BugCrowd CoinbasePro AppCobaltIO].each do |name|
    it "forwards YubiKey options only at #{name} login, not browser open" do
      ARGV.map! { |arg| arg == '--pwn-www-mod=GitHub' ? "--pwn-www-mod=#{name}" : arg }
      stub_const("PWN::WWW::#{name}", provider)
      expect(provider).to receive(:open).with(browser_type: :chrome).and_return(browser_obj)
      expect(provider).to receive(:login).with(hash_including(yubikey: { account: account, confirm: true, serial: serial }, mfa: false)).and_return(browser_obj)
      load script, true
    end
  end

  %w[Google Paypal].each do |name|
    it "rejects YubiKey for #{name} before password prompts or opening a browser" do
      ARGV.map! { |arg| arg == '--pwn-www-mod=GitHub' ? "--pwn-www-mod=#{name}" : arg }
      ARGV.delete('--password=fake-password')
      stub_const("PWN::WWW::#{name}", provider)
      expect(provider).not_to receive(:open)
      expect(provider).not_to receive(:login)
      expect { load script, true }.to raise_error(ArgumentError, /YubiKey OATH.*supported/)
    end
  end

  it 'requires a selected compatible provider before prompting or opening a browser' do
    ARGV.delete('--pwn-www-mod=GitHub')
    ARGV.delete('--password=fake-password')
    expect { load script, true }.to raise_error(ArgumentError, /YubiKey OATH.*supported/)
  end

  it 'rejects a serial without an exact account instead of silently disabling YubiKey' do
    ARGV.delete("--yubikey-account=#{account}")
    ARGV.delete('--password=fake-password')
    expect(provider).not_to receive(:open)
    expect { load script, true }.to raise_error(ArgumentError, /serial.*account/)
  end

  it 'requires --yubikey-confirm before password prompts or browser open' do
    ARGV.delete('--yubikey-confirm')
    ARGV.delete('--password=fake-password')
    expect(provider).not_to receive(:open)
    expect(provider).not_to receive(:login)
    expect { load script, true }.to raise_error(ArgumentError, /confirm: true.*HOTP.*authenticat/i)
  end

  it 'rejects confirmation without an account before password prompts or browser open' do
    ARGV.reject! { |arg| arg.start_with?('--yubikey-account=', '--yubikey-serial=') || arg == '--password=fake-password' }
    expect(provider).not_to receive(:open)
    expect(provider).not_to receive(:login)
    expect { load script, true }.to raise_error(ArgumentError, /--yubikey-confirm.*--yubikey-account/)
  end

  it 'does not accept a string value for the boolean --yubikey-confirm flag' do
    ARGV.map! { |arg| arg == '--yubikey-confirm' ? '--yubikey-confirm=true' : arg }
    expect(provider).not_to receive(:open)
    expect { load script, true }.to raise_error(OptionParser::NeedlessArgument)
  end

  ['', '123x', ' 123', '-1'].each do |invalid|
    it "rejects malformed serial #{invalid.inspect} before prompting or opening a browser" do
      ARGV.map! { |arg| arg == "--yubikey-serial=#{serial}" ? "--yubikey-serial=#{invalid}" : arg }
      ARGV.delete('--password=fake-password')
      expect(provider).not_to receive(:open)
      expect { load script, true }.to raise_error(ArgumentError, /serial.*decimal/)
    end
  end

  it 'validates an empty account before password prompts or browser open' do
    ARGV.map! { |arg| arg == "--yubikey-account=#{account}" ? '--yubikey-account=' : arg }
    ARGV.delete('--yubikey-confirm')
    ARGV.delete('--password=fake-password')
    expect(provider).not_to receive(:open)
    expect { load script, true }.to raise_error(ArgumentError, /account/)
  end

  it 'preserves an explicit MFA token from driver options rather than coercing it to true' do
    ARGV.reject! { |arg| arg.start_with?('--yubikey-') || arg == '--no-mfa' }
    driver_opts[:mfa] = '654321'
    expect(provider).to receive(:login).with(hash_including(mfa: '654321')).and_return(browser_obj)
    expect { load script, true }.not_to output(/fake-password|654321/).to_stdout
    expect(File.read(File.join(@tmpdir, 'results.txt'))).not_to match(/fake-password|654321/)
  end

  it 'keeps the generic driver options unchanged when no YubiKey is requested' do
    ARGV.reject! { |arg| arg.start_with?('--yubikey-') }
    ARGV.map! { |arg| arg == '--pwn-www-mod=GitHub' ? '--pwn-www-mod=Google' : arg }
    stub_const('PWN::WWW::Google', provider)
    expect(provider).to receive(:login) do |options|
      expect(options).not_to have_key(:yubikey)
      expect(options[:mfa]).to be(false)
      browser_obj
    end
    load script, true
  end

  it 'preserves the exact OATH name when the optional serial is omitted' do
    exact = " #{account} "
    ARGV.reject! { |arg| arg.start_with?('--yubikey-serial=') }
    ARGV.map! { |arg| arg == "--yubikey-account=#{account}" ? "--yubikey-account=#{exact}" : arg }
    expect(provider).to receive(:login).with(hash_including(yubikey: { account: exact, confirm: true })).and_return(browser_obj)
    expect { load script, true }.not_to output(/fake-password|012345/).to_stdout
  end

  it 'documents account, consent risks, and serial flags with the supported-provider boundary' do
    ARGV.replace(['--help'])
    expect do
      expect { load script, true }.to raise_error(SystemExit) { |error| expect(error.status).to eq(0) }
    end.to output(/--yubikey-account.*GitHub.*Synack.*Twitter.*BugCrowd.*CoinbasePro.*AppCobaltIO.*Paypal.*--yubikey-confirm.*HOTP.*delete.*corrupt.*--yubikey-serial/m).to_stdout
  end

  it 'rejects an explicit token conflicting with YubiKey before password prompts' do
    ARGV.delete('--no-mfa')
    ARGV.delete('--yubikey-confirm')
    ARGV.delete('--password=fake-password')
    driver_opts[:mfa] = '654321'
    expect(provider).not_to receive(:open)
    expect { load script, true }.to raise_error(ArgumentError, /yubikey.*mfa/i)
  end
end
