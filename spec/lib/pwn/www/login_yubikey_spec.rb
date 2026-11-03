# frozen_string_literal: true

require 'spec_helper'
require 'tty-prompt'

RSpec.shared_context 'offline MFA browser' do |selectors|
  let(:browser) { double('offline browser') }
  let(:browser_obj) { { browser: browser } }
  let(:credential_field) { double('credential field', set: nil, present?: true) }
  let(:otp_field) { double('OTP field', present?: true, exist?: true) }
  let(:absent_field) { double('absent field', present?: false, exist?: false) }
  let(:submit) { double('submit control', exist?: true, present?: true) }
  let(:yubikey) { { account: 'Example:tester@example.invalid', confirm: true, serial: '123456', device_path: '/fixture/native-device', timeout: 30 }.freeze }
  let(:login_opts) { { browser_obj: browser_obj, username: 'tester@example.invalid', password: 'fake-password', yubikey: yubikey } }

  before do
    @authenticated = false
    @otp_written = false
    @form_ready = false
    stub_const('PWN::Plugins::YubiKey', Module.new)
    allow(PWN::Plugins::YubiKey).to receive(:oath_code) do
      raise 'OATH requested before the MFA form was ready' unless @form_ready

      '012345'
    end
    allow(TTY::Prompt).to receive(:new).and_raise('unexpected interactive prompt')
    allow(browser).to receive(:goto)
    allow(browser).to receive(:url) { @authenticated ? selectors[:success] : selectors[:challenge] }
    allow(browser).to receive(:text_field).and_return(credential_field)
    allow(credential_field).to receive(:wait_until).and_return(credential_field)
    allow(browser).to receive(:text_field).with(selectors[:otp]).and_return(otp_field)
    Array(selectors[:absent]).each do |selector|
      allow(browser).to receive(:text_field).with(selector).and_return(absent_field)
    end
    allow(otp_field).to receive(:wait_until) do
      @form_ready = true
      otp_field
    end
    allow(otp_field).to receive(:set) { @otp_written = true }
    allow(browser).to receive_messages(button: submit, input: submit, span: submit)
    allow(submit).to receive(:wait_until).and_return(submit)
    allow(submit).to receive(:click)
    allow(submit).to receive(:click!) { @authenticated = true if @otp_written }
  end
end

RSpec.shared_examples 'YubiKey browser MFA' do |selectors|
  include_context 'offline MFA browser', selectors
  include_examples 'manual browser MFA'

  it 'documents explicit consent in the YubiKey example and explains native OATH effects' do
    expect { described_class.help }.to output(/Example yubikey: \{ account: 'EXACT_OATH_NAME', confirm: true.*HOTP.*authenticat/m).to_stdout
    expect { described_class.help }.not_to output(/ykman/).to_stdout
  end

  [nil, false].each do |mfa|
    it "types a leading-zero OATH code at the MFA form when mfa is #{mfa.inspect}" do
      login_opts[:mfa] = mfa unless mfa.nil?
      expect(otp_field).to receive(:set).with('012345') { @otp_written = true }
      expect(described_class.login(login_opts)).to equal(browser_obj)
      expect(PWN::Plugins::YubiKey).to have_received(:oath_code).with(yubikey).once
    end
  end

  it 'does not read a YubiKey when login completes without an MFA challenge' do
    @authenticated = true
    expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
    expect(otp_field).not_to receive(:set)
    expect(described_class.login(login_opts)).to equal(browser_obj)
  end

  it 'does not read a YubiKey if the MFA field never becomes present' do
    allow(otp_field).to receive(:wait_until).and_raise(IOError, 'MFA form unavailable')
    expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
    expect(otp_field).not_to receive(:set)
    expect { described_class.login(login_opts) }.to raise_error(IOError, 'MFA form unavailable')
  end

  it 'propagates a YubiKey failure without typing a token or prompting' do
    allow(PWN::Plugins::YubiKey).to receive(:oath_code).and_raise(IOError, 'device unavailable')
    expect(otp_field).not_to receive(:set)
    expect { described_class.login(login_opts) }.to raise_error(IOError, 'device unavailable')
  end
end

RSpec.shared_examples 'manual browser MFA' do
  it 'preserves the manual MFA prompt without a YubiKey option' do
    login_opts.delete(:yubikey)
    login_opts[:mfa] = true
    prompt = instance_double(TTY::Prompt)
    allow(TTY::Prompt).to receive(:new).and_return(prompt)
    expect(prompt).to receive(:ask).with('enter mfa token: ').and_return('012345')
    expect(otp_field).to receive(:set).with('012345') { @otp_written = true }
    expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
    expect(described_class.login(login_opts)).to equal(browser_obj)
  end

  it 'preserves disabled MFA when neither a token source nor mfa is selected' do
    login_opts.delete(:yubikey)
    expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
    expect(otp_field).not_to receive(:set)
    expect(described_class.login(login_opts)).to equal(browser_obj)
  end
end

RSpec.shared_examples 'MFA source validation' do
  [nil, false, 'true'].each do |confirm|
    it "rejects missing or nonliteral OATH consent #{confirm.inspect} before password prompts or browser navigation" do
      login_opts.delete(:password)
      unconfirmed = yubikey.except(:confirm)
      unconfirmed[:confirm] = confirm unless confirm.nil?
      expect(browser).not_to receive(:goto)
      expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
      expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
      expect { described_class.login(login_opts.merge(yubikey: unconfirmed)) }.to raise_error(ArgumentError, /confirm: true/)
    end
  end

  it 'documents the optional YubiKey configuration and explicit-token conflict' do
    expect { described_class.help }.to output(/yubikey:.*exact.*account.*serial.*reader.*device_path.*connection.*timeout.*conflict/m).to_stdout
  end

  [{ mfa: '654321' }, { mfa_token: '654321' }, { mfa: '654321', mfa_token: '  ' }].each do |conflict|
    it "rejects YubiKey with explicit token #{conflict.keys.inspect} before login or prompting" do
      login_opts.delete(:password)
      expect(browser).not_to receive(:goto)
      expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
      expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
      expect { described_class.login(login_opts.merge(conflict)) }.to raise_error(ArgumentError, /yubikey.*(?:mfa|token)/i)
    end
  end

  it 'rejects malformed YubiKey configuration before submitting a password' do
    expect(browser).not_to receive(:goto)
    expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
    expect { described_class.login(login_opts.merge(yubikey: {})) }.to raise_error(ArgumentError, /account/)
  end
end

RSpec.describe PWN::WWW::GitHub do
  include_examples 'MFA source validation'
  include_examples 'YubiKey browser MFA',
                   otp: { name: 'app_otp' },
                   challenge: 'https://github.com/sessions/two-factor',
                   success: 'https://github.com/'

  [
    { mfa: '012345' },
    { mfa_token: '012345' },
    { mfa: '654321', mfa_token: '012345' }
  ].each do |token_opts|
    it "preserves explicit tokens and mfa_token precedence for #{token_opts.keys.inspect}" do
      login_opts.delete(:yubikey)
      expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
      expect(otp_field).to receive(:set).with('012345') { @otp_written = true }
      expect(described_class.login(login_opts.merge(token_opts))).to equal(browser_obj)
    end
  end

  [{ id: 'app_totp' }, { name: 'otp' }].each do |selector|
    it "supports the alternate authenticator field #{selector.inspect}" do
      [{ name: 'app_otp' }, { id: 'app_totp' }, { name: 'otp' }].each do |absent|
        allow(browser).to receive(:text_field).with(absent).and_return(absent_field)
      end
      allow(browser).to receive(:text_field).with(selector).and_return(otp_field)
      expect(otp_field).to receive(:set).with('012345') { @otp_written = true }
      expect(described_class.login(login_opts)).to equal(browser_obj)
    end
  end

  it 'still accepts explicit SMS tokens without YubiKey' do
    login_opts.delete(:yubikey)
    [{ name: 'app_otp' }, { id: 'app_totp' }, { name: 'otp' }].each do |selector|
      allow(browser).to receive(:text_field).with(selector).and_return(absent_field)
    end
    allow(browser).to receive(:text_field).with(name: 'sms_otp').and_return(otp_field)
    expect(otp_field).to receive(:set).with('012345') { @otp_written = true }
    expect(described_class.login(login_opts.merge(mfa_token: '012345'))).to equal(browser_obj)
  end

  it 'consumes an explicit token once then prompts again on a repeated MFA form' do
    login_opts.delete(:yubikey)
    prompt = instance_double(TTY::Prompt)
    allow(TTY::Prompt).to receive(:new).and_return(prompt)
    expect(prompt).to receive(:ask).with('enter mfa token: ').once.and_return('012345')
    expect(otp_field).to(receive(:set).with('654321').ordered { @otp_written = false })
    expect(otp_field).to(receive(:set).with('012345').ordered { @otp_written = true })
    expect(described_class.login(login_opts.merge(mfa_token: '654321'))).to equal(browser_obj)
  end

  it 'refuses to type an OATH code into an SMS-only challenge' do
    %i[app_otp otp].each do |name|
      allow(browser).to receive(:text_field).with(name: name.to_s).and_return(absent_field)
    end
    allow(browser).to receive(:text_field).with(id: 'app_totp').and_return(absent_field)
    allow(browser).to receive(:text_field).with(name: 'sms_otp').and_return(otp_field)
    expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
    expect(otp_field).not_to receive(:set)
    expect { described_class.login(login_opts) }.to raise_error(ArgumentError, /OATH.*authenticator/)
  end
end

RSpec.describe PWN::WWW::Synack do
  include_examples 'MFA source validation'
  include_examples 'YubiKey browser MFA',
                   otp: { name: 'authy_token' },
                   challenge: 'https://login.synack.com/mfa',
                   success: 'https://platform.synack.com'
end

RSpec.describe PWN::WWW::Twitter do
  include_examples 'MFA source validation'
  include_examples 'YubiKey browser MFA',
                   otp: { id: 'challenge_response' },
                   challenge: 'https://twitter.com/login/challenge',
                   success: 'https://twitter.com/home'
end

RSpec.describe PWN::WWW::BugCrowd do
  include_examples 'MFA source validation'
  include_examples 'YubiKey browser MFA',
                   otp: { name: 'otp_attempt' },
                   challenge: 'https://bugcrowd.com/user/two_factor',
                   success: 'https://bugcrowd.com/programs'
end

RSpec.describe PWN::WWW::Paypal do
  include_context 'offline MFA browser',
                  otp: { id: 'security-code' },
                  challenge: 'https://www.paypal.com/signin/challenge',
                  success: 'https://www.paypal.com/myaccount/home'
  include_examples 'MFA source validation'
  include_examples 'manual browser MFA'

  [nil, false, true].each do |mfa|
    it "rejects unsupported OATH before login or prompting when mfa is #{mfa.inspect}" do
      login_opts.delete(:password)
      login_opts[:mfa] = mfa unless mfa.nil?
      expect(browser).not_to receive(:goto)
      expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
      expect(PWN::Plugins::YubiKey).not_to receive(:oath_code)
      expect { described_class.login(login_opts) }.to raise_error(ArgumentError, /PayPal.*OATH.*unsupported.*SMS/)
    end
  end

  it 'documents the SMS-only adapter limitation instead of claiming TOTP support' do
    expect { described_class.help }.to output(/OATH.*unsupported.*SMS/m).to_stdout
    expect { described_class.help }.to output(/unsupported even with confirm: true/m).to_stdout
  end

  it 'retains the SMS selection in manual mode' do
    login_opts.delete(:yubikey)
    allow(PWN::Plugins::AuthenticationHelper).to receive(:mfa).and_return('012345')
    expect(browser).to receive(:button).with(id: 'btnSelectSoftToken').and_return(submit)
    expect(described_class.login(login_opts.merge(mfa: true))).to equal(browser_obj)
  end
end

RSpec.describe PWN::WWW::CoinbasePro do
  include_examples 'MFA source validation'
  include_examples 'YubiKey browser MFA',
                   otp: { name: 'token' },
                   challenge: 'https://www.coinbase.com/signin/challenge',
                   success: 'https://pro.coinbase.com'
end

RSpec.describe PWN::WWW::AppCobaltIO do
  include_examples 'MFA source validation'
  include_examples 'YubiKey browser MFA',
                   otp: { id: 'code' },
                   challenge: 'https://app.cobalt.io/users/two_factor',
                   success: 'https://app.cobalt.io/dashboard'
end
