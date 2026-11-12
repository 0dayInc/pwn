# frozen_string_literal: true

require 'spec_helper'
require 'pwn/plugins/yubikey'

RSpec.describe PWN::Plugins::YubiKey do
  it 'has no executable dependencies' do
    expect(described_class.required_bins).to eq([])
  end

  it 'autoloads native children without probing a device' do
    %i[Protocol Transport OTP Management OATH HSMAuth PIV FIDO OpenPGP SecurityDomain].each do |name|
      expect(described_class.const_defined?(name, false)).to be(true)
    end
  end

  it 'checks host availability without discovery' do
    expect(described_class::Transport).to receive(:available?).with({}).and_return(true)
    expect(described_class::Transport).not_to receive(:devices)
    expect(described_class::Transport).not_to receive(:open)
    expect(described_class.available?).to be(true)
  end

  it 'returns native descriptors from explicit discovery' do
    records = [{ serial: '001234', protocol: :apdu, reader: 'Fixture NFC' }]
    expect(described_class::Transport).to receive(:devices).with({ serial: '001234', timeout: 3 }).and_return(records)
    expect(described_class.devices(serial: '001234', timeout: 3)).to equal(records)
  end

  it 'routes OTP info through the actual application and Protocol with owned cleanup' do
    connection = double('native transport', descriptor: { protocol: :apdu }, close: :closed)
    expect(described_class::Transport).to receive(:open) do |opened|
      expect(opened).to include(application: :otp, serial: '001234', reader: 'Fixture NFC')
      expect(opened[:timeout]).to be_positive.and be <= 3
      connection
    end
    expect(connection).to receive(:exchange).with(protocol: :apdu, data: ['00a4040007a0000005272001'].pack('H*'), timeout: kind_of(Numeric)).and_return(['0507010302009000'].pack('H*'))
    expect(connection).to receive(:close).once
    result = described_class.command(args: %w[otp info], serial: '001234', reader: 'Fixture NFC', timeout: 3)
    expect(result).to include(version: [5, 7, 1], programming_sequence: 3)
    expect(result[:slots][2][:configured]).to be(true)
  end
end

RSpec.describe PWN::Plugins::YubiKey, 'native family routing' do
  { otp: ['otp', :OTP, :otp], config: ['config', :Management, :management], oath: ['oath', :OATH, :oath],
    hsmauth: ['hsmauth', :HSMAuth, :hsmauth], piv: ['piv', :PIV, :piv], fido: ['fido', :FIDO, :fido],
    openpgp: ['openpgp', :OpenPGP, :openpgp], security_domain: ['sd', :SecurityDomain, :security_domain] }.each do |method, (prefix, name, application)|
    child = PWN::Plugins::YubiKey.const_get(name)
    it "provides local #{prefix} help without a transport" do
      expect(described_class::Transport).not_to receive(:open)
      expect(described_class::Transport).not_to receive(:devices)
      expect(described_class.public_send(method)).to include(application: application, operations: child.operations)
      child.operations.each do |operation|
        expect(described_class.cli_help(path: [prefix] + operation.split)).to include(operations: [operation])
      end
    end

    child.operations.each do |operation|
      it "routes #{prefix} #{operation} to the native child without rewriting options" do
        connection = double('caller connection', exchange: nil)
        expect(connection).not_to receive(:close)
        opts = { args: operation.split.freeze, confirm: true, connection: connection, timeout: 4 }.freeze
        expect(child).to receive(:execute).with(hash_including(opts.except(:connection))) do |received|
          expect(received[:connection]).to respond_to(:exchange, :descriptor)
          expect(received.keys).to match_array(opts.keys)
          :native_result
        end
        expect(described_class.public_send(method, opts)).to eq(:native_result)
        expect(opts[:args]).to eq(operation.split)
      end
    end
  end

  it 'forwards typed credentials and providers by identity, never as argv' do
    connection = double('caller connection', exchange: nil)
    pin = 'synthetic-pin'
    provider = ->(_name) { raise 'unexpected prompt' }
    expect(described_class::PIV).to receive(:execute).with(hash_including(args: %w[access change-pin], confirm: true, pin: pin, new_pin: 'synthetic-new-pin', secret_provider: provider)).and_return(:changed)
    expect(described_class.piv(args: %w[access change-pin], confirm: true, connection: connection, pin: pin, new_pin: 'synthetic-new-pin', secret_provider: provider)).to eq(:changed)
  end

  it 'calls Management.info for root info without inventing a config subcommand' do
    connection = double('caller connection', exchange: nil)
    expect(described_class::Management).to receive(:info).with(hash_including(connection: respond_to(:exchange))).and_return(version: [5, 7, 1])
    expect(described_class.info(connection: connection)).to eq(version: [5, 7, 1])
  end

  it 'dispatches root list and info aliases in Ruby' do
    expect(described_class::Transport).to receive(:devices).with({}).and_return([{ serial: '001234' }])
    expect(described_class.command(args: ['list'])).to eq([{ serial: '001234' }])
    connection = double('caller connection', exchange: nil)
    expect(described_class::Management).to receive(:info).with(hash_including(connection: respond_to(:exchange))).and_return(:information)
    expect(described_class.command(args: ['info'], connection: connection)).to eq(:information)
  end

  it 'rejects arbitrary help paths without opening a device' do
    expect(described_class::Transport).not_to receive(:open)
    [%w[otp delete 2 --force], ['--help'], ['script'], ['future']].each do |path|
      expect { described_class.cli_help(path: path) }.to raise_error(ArgumentError)
    end
    expect(described_class.command(args: ['--help'])).to include(backend: :native)
  end
end

RSpec.describe PWN::Plugins::YubiKey, 'native Vault and MFA helpers' do
  let(:connection) { double('native connection', descriptor: { protocol: :otp, serial: '001234' }, close: :closed) }

  it 'returns the raw RFC 2202 HMAC from the native OTP exchange' do
    expect(described_class::Transport).not_to receive(:open)
    expect(connection).not_to receive(:close)
    expect(connection).to receive(:exchange).with(protocol: :otp, command: 0, data: ''.b, response_length: 6, timeout: a_value_between(0, 3)).and_return(['050701030200'].pack('H*'))
    expect(connection).to receive(:exchange).with(protocol: :otp, command: 0x38, data: 'Hi There'.b.ljust(64, "\0"), response_length: 20, timeout: a_value_between(0, 3)).and_return(['b617318655057264e28bc0b6fb378c8ef146be00'].pack('H*'))
    opts = { challenge: 'Hi There', connection: connection, timeout: 3, confirm: true }.freeze
    result = described_class.challenge_response(opts)
    expect(result.unpack1('H*')).to eq('b617318655057264e28bc0b6fb378c8ef146be00')
    expect(result.encoding).to eq(Encoding::BINARY)
    expect(opts.keys).not_to include(:slot)
  end

  it 'programs and verifies a slot through the real OTP application without subprocesses' do
    key = ['0b' * 20].pack('H*').freeze
    before = ['050701030200'].pack('H*')
    after = ['050701040200'].pack('H*')
    expect(connection).to receive(:exchange).with(hash_including(command: 0)).ordered.and_return(before)
    expect(connection).to receive(:exchange).with(hash_including(command: 3)).ordered do |request|
      expect(request[:data].bytesize).to eq(58)
      expect(request[:data].byteslice(22, 16)).to eq(key.byteslice(0, 16))
      ''.b
    end
    expect(connection).to receive(:exchange).with(hash_including(command: 0)).ordered.and_return(after)
    expect(connection).to receive(:exchange).with(hash_including(command: 0)).ordered.and_return(after)
    expect(connection).to receive(:exchange).with(hash_including(command: 0x38)).ordered.and_return(['b617318655057264e28bc0b6fb378c8ef146be00'].pack('H*'))
    expect(described_class.provision_challenge_response(key: key, connection: connection, serial: '001234', confirm: true, verification_challenge: 'Hi There')).to eq(:verified)
  end

  it 'validates helper arguments before opening a transport' do
    expect(described_class::Transport).not_to receive(:open)
    [nil, '', 'x' * 65, [], 42].each do |challenge|
      expect { described_class.challenge_response(challenge: challenge, confirm: true) }.to raise_error(ArgumentError)
    end
    [0, 3, '2', 2.0, false].each do |slot|
      expect { described_class.challenge_response(challenge: 'x', slot: slot, confirm: true) }.to raise_error(ArgumentError)
    end
    [nil, '', "bad\n", 'x' * 65].each do |account|
      expect { described_class.oath_code(account: account, confirm: true) }.to raise_error(ArgumentError)
    end
    expect { described_class.oath_code(account: 'fixture', timestamp: -1, confirm: true) }.to raise_error(ArgumentError)
    expect { described_class.provision_challenge_response(key: 'k' * 19, serial: '001234', confirm: true) }.to raise_error(ArgumentError)
    expect { described_class.provision_challenge_response(key: 'k' * 20, confirm: true) }.to raise_error(ArgumentError)
  end

  it 'requires consent for provisioning and OATH calculation before opening a device' do
    expect(described_class::Transport).not_to receive(:open)
    [false, nil, 'true'].each do |confirm|
      expect { described_class.oath_code(account: 'fixture', confirm: confirm) }.to raise_error(described_class::ConfirmationRequired)
      expect { described_class.provision_challenge_response(key: 'k' * 20, serial: '001234', confirm: confirm) }.to raise_error(described_class::ConfirmationRequired)
    end
  end

  it 'calculates an existing-slot HMAC without a mutation consent flag' do
    connection = double('offline OTP', descriptor: { protocol: :otp }, close: :closed)
    allow(described_class::Transport).to receive(:open).and_return(connection)
    allow(described_class::OTP).to receive(:challenge_response).and_return('r'.b * 20)
    expect(described_class.challenge_response(challenge: 'fixture')).to eq('r'.b * 20)
  end
end

RSpec.describe PWN::Plugins::YubiKey, 'explicit native APDUs' do
  let(:connection) { double('smartcard connection', descriptor: { protocol: :apdu }, close: :closed) }

  it 'encodes typed APDUs through Protocol without putting payloads into argv' do
    expect(connection).not_to receive(:close)
    expect(connection).to receive(:exchange).with(protocol: :apdu, data: ['002000800431323334'].pack('H*'), timeout: kind_of(Numeric)).and_return(['9000'].pack('H*'))
    expect(described_class.apdu(ins: 0x20, p2: 0x80, data: '1234'.b, connection: connection, confirm: true)).to eq(''.b)
  end

  it 'selects an explicit application and sends legacy nonsecret compact APDUs in Ruby' do
    expect(connection).to receive(:exchange).with(hash_including(data: ['00a4040007a0000005272101'].pack('H*'))).ordered.and_return(['9000'].pack('H*'))
    expect(connection).to receive(:exchange).with(hash_including(data: ['00a1000000'].pack('H*'))).ordered.and_return(['720221619000'].pack('H*'))
    result = described_class.command(args: %w[apdu --app oath a1=], connection: connection, confirm: true)
    expect(result).to eq([{ data: ['72022161'].pack('H*'), status: 0x9000 }])
  end

  it 'supports explicit full APDU frames with status records and no automatic retries' do
    expect(connection).to receive(:exchange).with(hash_including(data: ['00a1000000'].pack('H*'))).once.and_return(['6982'].pack('H*'))
    expect(described_class.apdu(args: %w[--send-apdu 00a1000000], connection: connection, confirm: true)).to eq([{ data: ''.b, status: 0x6982 }])
  end

  it 'checks expected status words without including command payloads in errors' do
    expect(connection).to receive(:exchange).once.and_return(['6982'].pack('H*'))
    expect do
      described_class.apdu(args: ['20:31323334='], connection: connection, confirm: true)
    end.to raise_error(described_class::Protocol::APDUError) { |error|
      expect(error.status).to eq(0x6982)
      expect(error.full_message).not_to include('31323334')
    }
  end

  it 'rejects consent bypass, malformed frames and mixed inputs before transport acquisition' do
    expect(described_class::Transport).not_to receive(:open)
    expect { described_class.apdu(ins: 0xa1) }.to raise_error(described_class::ConfirmationRequired)
    [%w[--send-apdu xyz], %w[--app oath --send-apdu 00a1000000], %w[--send-apdu 00a1], ['invalid']].each do |args|
      expect { described_class.apdu(args: args, confirm: true) }.to raise_error(ArgumentError)
    end
    expect { described_class.apdu(ins: 256, confirm: true) }.to raise_error(ArgumentError)
    expect(described_class.apdu).to include(operations: ['apdu'])
  end
end
