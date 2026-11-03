# frozen_string_literal: true

require 'English'
require 'spec_helper'
require 'pwn/plugins/yubikey'

RSpec.describe PWN::Plugins::YubiKey, 'native credential boundaries' do
  before { expect(described_class::Transport).not_to receive(:open) }

  it 'rejects legacy process settings and unknown parameters without exposing values' do
    %i[ykman stdin input log_file max_output scp scp_ca scp_sd scp_oce arbitrary].each do |key|
      expect do
        described_class.command({ args: %w[otp info], key => 'synthetic-sensitive-value' })
      end.to raise_error(ArgumentError, /[Uu]nknown|[Uu]nsupported/) { |error|
        expect(error.full_message).not_to include('synthetic-sensitive-value')
      }
    end
  end

  it 'validates native selectors before opening anything' do
    { serial: ['', 123, ' 123', '123x', "123\n", false],
      reader: ['', false, "reader\n"], device_path: ['', false, "path\0"],
      timeout: [0, -1, Float::NAN, Float::INFINITY, '30', nil, false], connection: [false, Object.new] }.each do |key, values|
      values.each do |value|
        expect { described_class.command({ args: %w[otp info], key => value }) }.to raise_error(ArgumentError)
      end
    end
  end

  it 'requires literal consent for mutations and authentication regardless of force flags' do
    [%w[otp delete 2 --force], %w[fido reset], %w[piv access change-pin], %w[oath accounts code account],
     %w[sd reset], %w[config usb --list --disable OTP], %w[hsmauth credentials generate name]].each do |args|
      [nil, false, 'true', 1].each do |confirm|
        expect { described_class.command(args: args, confirm: confirm) }.to raise_error(described_class::ConfirmationRequired)
      end
    end
  end

  it 'rejects secret argv including inline flags and surplus positional credentials' do
    [%w[piv info --pin fixture-secret], %w[piv info --pin=fixture-secret],
     %w[fido access change-pin -nfixture-secret], %w[otp --access-code fixture-secret info],
     %w[otp chalresp 2 fixture-secret], %w[otp static 2 fixture-secret],
     %w[oath accounts add account fixture-secret], %w[oath accounts uri otpauth://fixture-secret],
     %w[sd keys import 1 1 fixture-secret], %w[info --log-file fixture-secret],
     %w[future reset fixture-secret]].each do |args|
      expect do
        described_class.command(args: args, confirm: true)
      end.to raise_error(ArgumentError) { |error| expect(error.full_message).not_to include('fixture-secret') }
    end
  end

  it 'rejects malformed argv without coercion or control characters' do
    ['info', [], [nil], [false], ["otp\0", 'info'], ['otp', 'info', 'x' * 65_537]].each do |args|
      expect { described_class.command(args: args) }.to raise_error(ArgumentError)
    end
  end
end

RSpec.describe PWN::Plugins::YubiKey, 'native connection lifetime' do
  let(:connection) { double('native connection', descriptor: { protocol: :apdu }, exchange: ''.b) }

  [IOError, Interrupt, PWN::Plugins::YubiKey::TimeoutError].each do |error_class|
    it "closes its owned connection on #{error_class}" do
      expect(described_class::Transport).to receive(:open).and_return(connection)
      expect(connection).to receive(:close).once
      expect(described_class::OTP).to receive(:execute) do |params|
        params[:connection].descriptor
        raise error_class, 'fixture failure'
      end
      expected = error_class == IOError ? described_class::CommandError : error_class
      expect { described_class.otp(args: ['info']) }.to raise_error(expected)
    end
  end

  it 'never closes a borrowed connection even on an APDU failure' do
    expect(connection).not_to receive(:close)
    expect(connection).to receive(:exchange).and_return(['6982'].pack('H*'))
    expect do
      described_class.oath(args: ['info'], connection: connection)
    end.to raise_error(described_class::Protocol::APDUError) { |error| expect(error.status).to eq(0x6982) }
  end

  it 'suppresses native IO diagnostic secrets and exception causes' do
    expect(described_class::Transport).to receive(:open).and_raise(IOError, 'synthetic-sensitive-path')
    expect do
      described_class.otp(args: ['info'])
    end.to raise_error(described_class::CommandError) { |error|
      expect(error.full_message).not_to include('synthetic-sensitive-path')
      expect(error.cause).to be_nil
    }
  end

  [false, true].each do |owned|
    it "wraps an explicit secure channel and preserves #{owned ? 'owned cleanup' : 'caller ownership'}" do
      options = { scp: :scp03, kvn: 7, key_enc: 'e' * 16, key_mac: 'm' * 16 }.freeze
      wrapper = double('secure connection', exchange: ''.b)
      expect(described_class::Transport).to receive(:open).and_return(connection) if owned
      if owned
        expect(connection).to receive(:close).once
      else
        expect(connection).not_to receive(:close)
      end
      expect(described_class::SecurityDomain).to receive(:secure_connection) do |params|
        expect(params).to include(options)
        expect(params[:confirm]).to be(true)
        expect(params[:connection].descriptor).to eq(protocol: :apdu)
        params[:connection].close # SCP invalidation must not close the borrowed handle.
        wrapper
      end
      expect(wrapper).to receive(:close).once
      expect(described_class::OATH).to receive(:execute).with(hash_including(connection: wrapper, args: ['info'], confirm: true)).and_return(:secure_result)
      selected = owned ? {} : { connection: connection }
      expect(described_class.oath(selected.merge(args: ['info'], confirm: true, secure_channel: options))).to eq(:secure_result)
      expect(options).not_to have_key(:connection)
    end
  end

  it 'never falls back to plaintext after secure-channel authentication failure' do
    expect(described_class::Transport).to receive(:open).and_return(connection)
    expect(connection).to receive(:close).once
    expect(described_class::SecurityDomain).to receive(:secure_connection).and_raise(described_class::ResponseError, 'SCP authentication failed')
    expect(described_class::OATH).not_to receive(:execute)
    expect do
      described_class.oath(args: ['info'], confirm: true, secure_channel: { scp: :scp03, kvn: 1, key_enc: 'e' * 16, key_mac: 'm' * 16 })
    end.to raise_error(described_class::ResponseError, /SCP/)
  end

  it 'validates secure-channel options and explicit consent before opening hardware' do
    expect(described_class::Transport).not_to receive(:open)
    [false, 'scp03', {}, { scp: :scp03, confirm: true }, { connection: connection }].each do |value|
      expect { described_class.oath(args: ['info'], confirm: true, secure_channel: value) }.to raise_error(ArgumentError)
    end
    expect do
      described_class.oath(args: ['info'], secure_channel: { scp: :scp03, kvn: 1, key_enc: 'e' * 16, key_mac: 'm' * 16 })
    end.to raise_error(described_class::ConfirmationRequired)
  end

  it 'loads the facade in a fresh Ruby without process libraries or device discovery' do
    source = <<~RUBY
      before = $LOADED_FEATURES.dup
      require 'pwn/plugins/yubikey'
      added = $LOADED_FEATURES - before
      abort 'process library loaded' if added.any? { |path| path.match?(%r{/(?:open3|pty)(?:\\.|/)}) }
      abort 'native transport eagerly loaded' unless PWN::Plugins::YubiKey.autoload?(:Transport)
      puts 'native-only'
    RUBY
    output = IO.popen([RbConfig.ruby, '-Ilib', '-e', source], &:read)
    expect($CHILD_STATUS).to be_success
    expect(output).to eq("native-only\n")
    text = File.read(File.expand_path('../../../../lib/pwn/plugins/yubikey.rb', __dir__))
    expect(text).not_to match(/Open3|PTY|\b(?:system|spawn|popen|exec)\s*\(/)
  end
end

RSpec.describe PWN::Plugins::YubiKey, 'total native operation deadline' do
  before do
    @now = 100.0
    allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC) { @now }
  end

  it 'shares one budget across acquisition, OATH SELECT, LIST and calculation' do
    connection = double('APDU transport', descriptor: { protocol: :apdu })
    expect(described_class::Transport).to receive(:open).with(hash_including(application: :oath, timeout: 3)) do
      @now += 1
      connection
    end
    expect(connection).to receive(:close).once
    expect(connection).to receive(:exchange).with(hash_including(data: ['00a4040007a0000005272101'].pack('H*'), timeout: 2)).ordered do
      @now += 1
      ['79030507017101739000'].pack('H*')
    end
    expect(connection).to receive(:exchange).with(hash_including(data: ['00a1000000'].pack('H*'), timeout: 1)).ordered do
      @now += 2
      ['720221619000'].pack('H*')
    end
    expect do
      described_class.oath_code(account: 'a', confirm: true, timeout: 3, timestamp: 59)
    end.to raise_error(described_class::TimeoutError)
  end

  it 'charges secure-channel authentication to the same budget on a borrowed connection' do
    connection = double('APDU transport', descriptor: { protocol: :apdu })
    expect(connection).not_to receive(:close)
    expect(described_class::SecurityDomain).to receive(:secure_connection) do |params|
      expect(params[:timeout]).to eq(3)
      @now += 2
      params[:connection]
    end
    expect(connection).to receive(:exchange).with(hash_including(timeout: 1)).once do
      @now += 2
      ['79030507017101739000'].pack('H*')
    end
    expect do
      described_class.oath(args: ['info'], connection: connection, confirm: true, timeout: 3,
                           secure_channel: { scp: :scp03, kvn: 1, key_enc: 'e' * 16, key_mac: 'm' * 16 })
    end.to raise_error(described_class::TimeoutError)
  end

  it 'refuses exchanges when acquisition exhausts the budget and still closes the owned handle' do
    connection = double('late native transport', descriptor: { protocol: :otp })
    expect(described_class::Transport).to receive(:open) do
      @now += 4
      connection
    end
    expect(connection).not_to receive(:exchange)
    expect(connection).to receive(:close).once
    expect { described_class.otp(args: ['info'], timeout: 3) }.to raise_error(described_class::TimeoutError)
  end
end

RSpec.describe PWN::Plugins::YubiKey, 'validation before native acquisition' do
  it 'does not open a device for missing PIV credentials or an invalid native slot' do
    expect(described_class::Transport).not_to receive(:open)
    expect { described_class.piv(args: %w[access change-pin], confirm: true) }.to raise_error(ArgumentError)
    expect { described_class.otp(args: %w[delete invalid-slot], confirm: true) }.to raise_error(ArgumentError)
  end

  it 'runs explicit cache-only forget without discovering or opening a YubiKey' do
    cache = double('caller encrypted cache', encrypted?: true, clear: nil, empty?: true)
    expect(described_class::Transport).not_to receive(:open)
    expect(described_class::Transport).not_to receive(:devices)
    expect(cache).to receive(:clear).once
    expect(described_class.oath(args: %w[access forget --all], confirm: true, encrypted_cache: cache)).to eq(forgotten: :all, verified: true)
  end

  it 'allows native read-only inventory without authorizing authentication or changes' do
    connection = double('caller connection', exchange: nil)
    expect(described_class::Management).to receive(:execute).with(hash_including(args: %w[usb --list])).and_return(:inventory)
    expect(described_class.config(args: %w[usb --list], connection: connection)).to eq(:inventory)
    expect(described_class::HSMAuth).to receive(:execute).with(hash_including(args: %w[credentials list])).and_return([])
    expect(described_class.hsmauth(args: %w[credentials list], connection: connection)).to eq([])
    expect do
      described_class.config(args: %w[usb --list], disable: 'OTP', connection: connection)
    end.to raise_error(described_class::ConfirmationRequired)
  end

  it 'keeps OATH list read-only only when no authentication or cache state is requested' do
    connection = double('caller connection', descriptor: { protocol: :apdu })
    expect(connection).to receive(:exchange).with(hash_including(data: ['00a4040007a0000005272101'].pack('H*'))).ordered.and_return(['79030507017101739000'].pack('H*'))
    expect(connection).to receive(:exchange).with(hash_including(data: ['00a1000000'].pack('H*'))).ordered.and_return(['9000'].pack('H*'))
    expect(described_class.oath(args: %w[accounts list], connection: connection)).to eq([])
    expect do
      described_class.oath(args: %w[accounts list], password: 'synthetic', connection: connection)
    end.to raise_error(described_class::ConfirmationRequired)
  end

  it 'documents every public root API with native behavior and no executable backend' do
    output = StringIO.new
    prior = $stdout
    $stdout = output
    described_class.help
    (described_class.singleton_methods(false) - [:help]).each do |method|
      expect(output.string).to include("PWN::Plugins::YubiKey.#{method}")
    end
    expect(output.string).to include('native', 'secret_provider', 'operator:', 'total')
    expect(output.string).not_to include('wrapper for official', 'executable path')
  ensure
    $stdout = prior
  end
end
