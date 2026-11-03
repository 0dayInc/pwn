# frozen_string_literal: true

require 'spec_helper'
require 'pty'
require 'io/console'
require 'io/wait'
require 'timeout'
require 'fcntl'

RSpec.describe PWN::Plugins::YubiKey, 'private native operator input' do
  let(:connection) { double('caller native connection', exchange: nil) }

  it 'reads a masked credential directly from the console and returns no secrets or device results' do
    master, terminal = PTY.open
    flags = terminal.fcntl(Fcntl::F_GETFL)
    screen = ''.b
    captured = nil
    opts = { args: %w[oath accounts list], confirm: true, operator: true, terminal: terminal, connection: connection, timeout: 5 }.freeze
    expect(described_class::OATH).to receive(:execute) do |received|
      captured = received[:secret_provider].call(:password)
      expect(captured).to eq('synthetic-password')
      'sensitive-device-output'
    end
    operator = Thread.new do
      Timeout.timeout(5) do
        screen << master.readpartial(1024) until screen.include?('YubiKey password: ')
        expect(terminal.echo?).to be(false)
        master.write("synthetic-password\n")
      end
    end
    expect do
      expect(described_class.interact(opts)).to eq(:completed)
    end.not_to output.to_stdout
    operator.value
    screen << master.readpartial(1024) while master.wait_readable(0)
    expect(screen).not_to include('synthetic-password', 'sensitive-device-output')
    expect(captured).to eq("\0" * 'synthetic-password'.bytesize)
    expect(terminal).not_to be_closed
    expect(terminal.echo?).to be(true)
    expect(terminal.fcntl(Fcntl::F_GETFL)).to eq(flags)
    expect(opts).not_to have_key(:secret_provider)
  ensure
    operator&.kill&.join
    master&.close
    terminal&.close
  end

  it 'requires literal operator opt-in and refuses agent request contexts before looking up a console' do
    expect(IO).not_to receive(:console)
    expect(described_class::Transport).not_to receive(:open)
    expect { described_class.interact(args: %w[oath accounts list]) }.to raise_error(described_class::ConfirmationRequired)
    expect { described_class.interact(args: %w[oath accounts list], confirm: true) }.to raise_error(ArgumentError, /operator/)
    prior = Thread.current[:pwn_request_runtime]
    Thread.current[:pwn_request_runtime] = Object.new
    expect do
      described_class.interact(args: %w[oath accounts list], confirm: true, operator: true)
    end.to raise_error(ArgumentError, /private.*operator|agent/)
  ensure
    Thread.current[:pwn_request_runtime] = prior
  end

  it 'rejects virtual terminals, credential argv and an overriding provider before device acquisition' do
    expect(described_class::Transport).not_to receive(:open)
    expect do
      described_class.interact(args: %w[oath accounts list], confirm: true, operator: true, terminal: StringIO.new)
    end.to raise_error(ArgumentError, /terminal/)
    expect do
      described_class.interact(args: %w[piv info --pin synthetic-secret], confirm: true, operator: true, terminal: StringIO.new)
    end.to raise_error(ArgumentError)
    expect do
      described_class.interact(args: %w[oath accounts list], confirm: true, operator: true, secret_provider: ->(_name) { 'synthetic-secret' })
    end.to raise_error(ArgumentError)
  end

  [false, true].each do |interrupt|
    it "restores echo and descriptor flags on #{interrupt ? 'interruption' : 'input timeout'} without closing caller IO" do
      master, terminal = PTY.open
      flags = terminal.fcntl(Fcntl::F_GETFL) | Fcntl::O_NONBLOCK
      terminal.fcntl(Fcntl::F_SETFL, flags)
      expect(described_class::OATH).to receive(:execute) { |opts| opts[:secret_provider].call(:password) }
      worker = Thread.new do
        Thread.current.report_on_exception = false
        described_class.interact(args: %w[oath accounts list], confirm: true, operator: true, terminal: terminal, connection: connection, timeout: interrupt ? 5 : 0.2)
      end
      screen = ''.b
      Timeout.timeout(5) { screen << master.readpartial(1024) until screen.include?('YubiKey password: ') }
      worker.raise(Interrupt) if interrupt
      expect { Timeout.timeout(5) { worker.value } }.to raise_error(interrupt ? Interrupt : described_class::TimeoutError)
      expect(terminal).not_to be_closed
      expect(terminal.echo?).to be(true)
      expect(terminal.fcntl(Fcntl::F_GETFL)).to eq(flags)
    ensure
      worker.kill.join if worker&.alive?
      master&.close
      terminal&.close
    end
  end
end

RSpec.describe PWN::Plugins::YubiKey, 'terminal access and descriptor ownership' do
  %i[file wrapper].each do |kind|
    %w[r w].each do |mode|
      it "rejects #{kind} terminal mode #{mode} before consuming input or opening a device" do
        master, slave = PTY.open
        terminal = kind == :file ? File.open(slave.path, mode) : IO.for_fd(slave.fileno, mode, autoclose: false)
        slave.echo = false
        master.write("untouched-input\n")
        expect(slave.wait_readable(1)).to eq(slave)
        flags = terminal.fcntl(Fcntl::F_GETFL)
        expect(flags & Fcntl::O_ACCMODE).to eq(Fcntl::O_RDWR) if kind == :wrapper
        expect(described_class::Transport).not_to receive(:open)
        expect(terminal).not_to receive(:getpass)
        expect do
          described_class.interact(args: %w[piv reset --force], confirm: true, operator: true, terminal: terminal)
        end.to raise_error(ArgumentError, /readable and writable/)
        expect(terminal).not_to be_closed
        expect(terminal.fcntl(Fcntl::F_GETFL)).to eq(flags)
        expect(slave.echo?).to be(false)
        expect(Timeout.timeout(1) { slave.gets }).to eq("untouched-input\n")
        expect(master.wait_readable(0)).to be_nil
      ensure
        terminal&.close
        master&.close
        slave&.close
      end
    end
  end

  it 'uses IO.console by default without consuming pending input for a read-only operation' do
    master, terminal = PTY.open
    terminal.echo = false
    master.write("queued-fixture\n")
    expect(terminal.wait_readable(1)).to eq(terminal)
    flags = terminal.fcntl(Fcntl::F_GETFL)
    connection = double('native OTP connection', descriptor: { protocol: :otp })
    expect(connection).to receive(:exchange).with(hash_including(command: 0)).and_return(['050701030200'].pack('H*'))
    expect(connection).not_to receive(:close)
    expect(IO).to receive(:console).and_return(terminal)
    expect(described_class.interact(args: %w[otp info], confirm: true, operator: true, connection: connection)).to eq(:completed)
    expect(terminal.gets).to eq("queued-fixture\n")
    expect(terminal.echo?).to be(false)
    expect(terminal.fcntl(Fcntl::F_GETFL)).to eq(flags)
  ensure
    master&.close
    terminal&.close
  end
end
