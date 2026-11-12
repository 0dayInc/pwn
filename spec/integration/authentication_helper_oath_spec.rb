# frozen_string_literal: true

require 'spec_helper'
require 'tty-prompt'

RSpec.describe 'AuthenticationHelper native OATH integration' do
  let(:account) { '-例:tester@example.invalid .+  ' }
  let(:serial) { '00123456' }
  let(:connection) { double('offline APDU connection', descriptor: { protocol: :apdu, serial: serial }, close: :closed) }
  let(:yubikey) { { account: account, confirm: true, serial: serial, connection: connection, timeout: 5 }.freeze }
  let(:select_apdu) { ['00a4040007a0000005272101'].pack('H*') }
  let(:list_apdu) { ['00a1000000'].pack('H*') }
  let(:calculate_apdu) do
    body = [0x71, account.bytesize].pack('CC') + account.b + [0x74, 8].pack('CC') + [1].pack('Q>')
    [0, 0xa2, 0, 1, body.bytesize].pack('C*') + body
  end

  before do
    @ready = false
    @frames = []
    allow(Time).to receive(:now).and_return(Time.at(59))
    allow(TTY::Prompt).to receive(:new).and_raise('unexpected interactive prompt')
    expect(PWN::Plugins::YubiKey::Transport).not_to receive(:open)
    expect(connection).not_to receive(:close)
    allow(connection).to receive(:exchange) do |request|
      expect(@ready).to be(true)
      expect(request[:protocol]).to eq(:apdu)
      @frames << request[:data]
      case request[:data]
      when select_apdu
        [0x79, 3, 5, 7, 1, 0x71, 8].pack('C*') + 'fixture!'.b + "\x90\0".b
      when list_apdu
        [0x72, account.bytesize + 1, 0x21].pack('C*') + account.b + "\x90\0".b
      when calculate_apdu
        [0x76, 5, 8, 12_345].pack('CCCN') + "\x90\0".b
      else
        raise 'Unexpected APDU in offline OATH fixture'
      end
    end
  end

  it 'runs the real helper, root facade, OATH.code and Protocol against a fake APDU transport' do
    @ready = true
    options = { yubikey: yubikey }.freeze
    expect do
      expect(PWN::Plugins::AuthenticationHelper.mfa(options)).to eq('00012345')
    end.not_to output.to_stdout
    expect(@frames).to eq([select_apdu, list_apdu, calculate_apdu])
    expect(options[:yubikey]).to equal(yubikey)
  end

  [nil, false, 'true'].each do |confirm|
    it "rejects unconfirmed OATH #{confirm.inspect} before any APDU or prompt" do
      expect do
        PWN::Plugins::AuthenticationHelper.mfa(yubikey: yubikey.merge(confirm: confirm).freeze)
      end.to raise_error(ArgumentError, /confirm: true/)
      expect(@frames).to be_empty
    end
  end

  it 'propagates exact-account errors without calculation, credential repair or manual fallback' do
    @ready = true
    expect do
      PWN::Plugins::AuthenticationHelper.mfa(yubikey: yubikey.merge(account: 'missing@example.invalid'))
    end.to raise_error(PWN::Plugins::YubiKey::ResponseError, /exact account/)
    expect(@frames).to eq([select_apdu, list_apdu])
  end

  context 'through the real GitHub login and helper' do
    let(:browser) { double('offline browser') }
    let(:browser_obj) { { browser: browser } }
    let(:credential_field) { double('offline credential field', set: nil, present?: true) }
    let(:otp_field) { double('offline OATH field', present?: true, exist?: true) }
    let(:submit) { double('offline submit', exist?: true) }
    let(:login_opts) { { browser_obj: browser_obj, username: 'tester@example.invalid', password: 'fake-password', mfa: false, yubikey: yubikey } }

    before do
      @authenticated = false
      @otp_written = false
      allow(PWN::WWW::GitHub).to receive(:sleep)
      allow(browser).to receive(:goto)
      allow(browser).to receive(:url) { @authenticated ? 'https://github.com/' : 'https://github.com/sessions/two-factor' }
      allow(browser).to receive(:text_field).and_return(credential_field)
      allow(credential_field).to receive(:wait_until).and_return(credential_field)
      allow(browser).to receive(:text_field).with(name: 'app_otp').and_return(otp_field)
      allow(otp_field).to receive(:wait_until) do
        expect(@frames).to be_empty
        @ready = true
        otp_field
      end
      allow(browser).to receive(:input).with(name: 'commit').and_return(submit)
      allow(submit).to receive(:click!) { @authenticated = true if @otp_written }
    end

    it 'types actual native OATH digits only after the authenticator field is ready' do
      expect(otp_field).to receive(:set).with('00012345') { @otp_written = true }
      expect(PWN::WWW::GitHub.login(login_opts)).to equal(browser_obj)
      expect(@frames).to eq([select_apdu, list_apdu, calculate_apdu])
    end

    it 'does not touch a token for an already authenticated redirect' do
      @authenticated = true
      expect(otp_field).not_to receive(:set)
      expect(PWN::WWW::GitHub.login(login_opts)).to equal(browser_obj)
      expect(@frames).to be_empty
    end

    it 'rejects absent consent before asking for a password or navigating' do
      expect(PWN::Plugins::AuthenticationHelper).not_to receive(:mask_password)
      expect(browser).not_to receive(:goto)
      expect do
        PWN::WWW::GitHub.login(login_opts.except(:password).merge(yubikey: yubikey.except(:confirm)))
      end.to raise_error(ArgumentError, /confirm: true/)
      expect(@frames).to be_empty
    end
  end
end
