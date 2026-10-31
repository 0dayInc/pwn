# frozen_string_literal: true

require 'spec_helper'
require 'pwn/plugins/capability_broker'
require 'tmpdir'
require 'rbconfig'
require 'etc'

describe 'Native capability broker daemon' do
  def daemon
    PWN::Plugins::CapabilityBroker::Daemon
  end

  def dispatch(request, peer_uid: Process.uid)
    daemon.dispatch(request: request, peer_uid: peer_uid, uid: Process.uid, interfaces: ['lo'])
  end

  it 'sends only bounded decoded Ethernet frames through an allowlisted AF_PACKET socket' do
    expect(dispatch({ 'operation' => 'raw_send', 'iface' => 'lo', 'frame' => '!!' })[:ok]).to eq(false)
    expect(dispatch({ 'operation' => 'raw_send', 'iface' => 'lo', 'frame' => ['tiny'].pack('m0') })[:ok]).to eq(false)
    raw = double('raw socket', close: nil)
    expect(Socket).to receive(:new).with(Socket::AF_PACKET, Socket::SOCK_RAW, [3].pack('n').unpack1('S')).and_return(raw)
    expect(Socket).to receive(:getifaddrs).and_return([double(name: 'lo', ifindex: 1)])
    expect(raw).to receive(:bind).with([Socket::AF_PACKET, 3, 1, 0, 0, 0, "\0" * 8].pack('S n i S C C a8'))
    expect(raw).to receive(:wait_writable).with(5).and_return(true)
    expect(raw).to receive(:sendmsg_nonblock).with('x' * 14).and_return(14)
    expect(dispatch({ 'operation' => 'raw_send', 'iface' => 'lo', 'frame' => ['x' * 14].pack('m0') })).to include(ok: true, bytes: 14)
  end

  it 'captures bounded in-memory Ethernet pcap and closes the raw socket' do
    expect(dispatch({ 'operation' => 'capture', 'iface' => 'lo', 'count' => 129 })[:ok]).to eq(false)
    expect(dispatch({ 'operation' => 'capture', 'iface' => 'lo', 'timeout' => 31 })[:ok]).to eq(false)
    raw = double('raw socket', close: nil)
    allow(daemon).to receive(:packet_socket).with(iface: 'lo').and_return(raw)
    expect(raw).to receive(:wait_readable).with(a_value_between(0, 1)).and_return(true)
    expect(raw).to receive(:recv_nonblock).with(4096, exception: false).and_return('packet')
    result = dispatch({ 'operation' => 'capture', 'iface' => 'lo', 'count' => 1, 'timeout' => 1 })
    expect(result).to include(ok: true, count: 1)
    data = result[:pcap].unpack1('m0')
    expect(data[0, 24].unpack('VvvVVVV')).to eq([0xa1b2c3d4, 2, 4, 0, 0, 4096, 1])
    expect(data[32, 8].unpack('VV')).to eq([6, 6])
    expect(data[40..]).to eq('packet')
  end

  it 'queries typed IPv4 and IPv6 neighbor caches without a shell' do
    expect(dispatch({ 'operation' => 'arp', 'iface' => 'lo', 'address' => '::1' })[:ok]).to eq(false)
    expect(dispatch({ 'operation' => 'nd', 'iface' => 'lo', 'address' => '127.0.0.1' })[:ok]).to eq(false)
    expect(dispatch({ 'operation' => 'arp', 'iface' => 'lo', 'address' => '127.0.0.1/8' })[:ok]).to eq(false)
    expect(daemon).to receive(:bounded_command).with(argv: ['/usr/sbin/ip', '-j', '-4', 'neigh', 'show', 'to', '127.0.0.1', 'dev', 'lo']).and_return('[]')
    expect(dispatch({ 'operation' => 'arp', 'iface' => 'lo', 'address' => '127.0.0.1' })).to include(ok: true, neighbors: [])
    expect(daemon).to receive(:bounded_command).with(argv: ['/usr/sbin/ip', '-j', '-6', 'neigh', 'show', 'to', '::1', 'dev', 'lo']).and_return('[]')
    expect(dispatch({ 'operation' => 'nd', 'iface' => 'lo', 'address' => '::1' })).to include(ok: true, neighbors: [])
  end

  it 'bounds subprocess output and time and reports a failed query' do
    expect(daemon.send(:bounded_command, argv: ['/usr/bin/printf', '[]'])).to eq('[]')
    expect { daemon.send(:bounded_command, argv: ['/bin/false']) }.to raise_error(/neighbor query failed/)
    expect { daemon.send(:bounded_command, argv: ['/usr/bin/printf', '%1000001s', '']) }.to raise_error(/output too large/)
    expect { daemon.send(:bounded_command, argv: ['/bin/sleep', '1'], timeout: 0.02) }.to raise_error(Timeout::Error)
  end

  it 'serves bounded JSON using actual Unix peer credentials and rejects incomplete requests' do
    [['{"operation":"status"}\n'.gsub('\\n', "\n"), true], ['{}', false], ["#{'x' * 100_000}\n", false], ["not json\n", false]].each do |payload, ok|
      server, client = UNIXSocket.pair
      worker = Thread.new do
        daemon.serve_client(client: server, uid: Process.uid, interfaces: ['lo'])
      ensure
        server.close
      end
      worker.report_on_exception = false
      client.write(payload)
      client.close_write
      expect(JSON.parse(client.gets)['ok']).to eq(ok)
      worker.value
    ensure
      server&.close
      client&.close
    end
  end

  it 'times out idle Unix clients using a total request deadline' do
    server, client = UNIXSocket.pair
    expect { daemon.serve_client(client: server, uid: Process.uid, interfaces: ['lo'], timeout: 0.02) }.to raise_error(Timeout::Error)
  ensure
    server&.close
    client&.close
  end

  # Fork the complete smoke so both daemon and authenticated client use the
  # same unprivileged identity, without changing the RSpec runner's credentials.
  def unprivileged_smoke(directory)
    account = Etc.getpwnam('nobody') if Process.euid.zero?
    if account
      raise 'smoke account must have nonzero UID and GID' if account.uid.zero? || account.gid.zero?

      File.chown(account.uid, account.gid, directory)
    end
    report = File.join(directory, 'smoke.log')
    File.open(report, 'w') do |output|
      worker = fork do
        Process.setpgrp
        begin
          if account
            Process.groups = []
            Process::GID.change_privilege(account.gid)
            Process::UID.change_privilege(account.uid)
            expect(Process.groups).to eq([])
          end
          expect(Process.uid).not_to eq(0)
          expect(Process.euid).not_to eq(0)
          yield
          exit! 0
        rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
          output.write(e.full_message)
          output.flush
          exit! 1
        end
      end
      begin
        _, result = Timeout.timeout(15) { Process.wait2(worker) }
        expect(result.success?).to eq(true), File.read(report)
      ensure
        # Kill the private process group on failure/timeout, including a daemon
        # left behind if the smoke worker died before reaching its own ensure.
        begin
          Process.kill('KILL', -worker)
        rescue Errno::ESRCH
          nil
        end
        begin
          Process.wait(worker)
        rescue Errno::ECHILD
          nil
        end
      end
    end
  end

  it 'runs the real native executable without privileges and cleans up its protected socket' do
    Dir.mktmpdir('capd-spec-') do |directory|
      unprivileged_smoke(directory) do
        path = File.join(directory, 'control.sock')
        log = File.join(directory, 'daemon.log')
        pid = Process.spawn(RbConfig.ruby, File.expand_path('../../../../../bin/pwn-capd', __dir__), '--uid', Process.uid.to_s, '--interface', 'lo', '--socket', path, out: log, err: log)
        begin
          Timeout.timeout(5) do
            until File.socket?(path)
              raise File.read(log) if Process.waitpid(pid, Process::WNOHANG)

              sleep 0.01
            end
          end
          expect(File.readlink("/proc/#{pid}/exe")).to include('ruby')
          expect(File.stat(path).mode & 0o777).to eq(0o600)
          expect(PWN::Plugins::CapabilityBroker.request(socket: path, operation: 'status')).to include(ok: true, interfaces: ['lo'])
          expect(File.stat(path).uid).to eq(Process.uid)
          expect(File.stat(directory).mode & 0o777).to eq(0o700)
          status = File.read("/proc/#{pid}/status")
          expect(status[/^Uid:\s+(.+)/, 1].split.map(&:to_i)).to eq([Process.uid] * 4)
          expect(status[/^Gid:\s+(.+)/, 1].split.map(&:to_i)).to eq([Process.gid] * 4)
          expect(status[/^Groups:[^\S\n]*([^\n]*)/, 1].split.map(&:to_i).sort).to eq(Process.groups.sort)
          expect(status[/^NoNewPrivs:\s+(\d+)/, 1]).to eq('1')
          expect(status[/^CapEff:\s+(\h+)/, 1].to_i(16) & ~((1 << 12) | (1 << 13))).to eq(0)
          expect(status[/^CapPrm:\s+(\h+)/, 1].to_i(16) & ~((1 << 12) | (1 << 13))).to eq(0)
          expect(status[/^CapInh:\s+(\h+)/, 1].to_i(16)).to eq(0)
          expect(PWN::Plugins::CapabilityBroker.request(socket: path, operation: 'exec')[:ok]).to eq(false)
        ensure
          begin
            Process.kill('TERM', pid)
            _, result = Timeout.timeout(5) { Process.wait2(pid) }
          rescue Errno::ESRCH, Errno::ECHILD
            nil
          rescue Timeout::Error
            Process.kill('KILL', pid)
            Process.wait(pid)
            raise
          end
        end
        expect(result.success?).to eq(true), File.read(log)
        expect { Process.waitpid(pid, Process::WNOHANG) }.to raise_error(Errno::ECHILD)
        expect(File.exist?(path)).to eq(false)
      end
    end
  end

  it 'retains only already-held network bits and clears both inheritable words' do
    expect(daemon).to receive(:prctl).with(38, 1, 0, 0, 0).and_return(0)
    expect(daemon).to receive(:capget) do |header, data|
      expect(header.read_array_of_uint32(2)).to eq([0x20080522, 0])
      data.write_array_of_uint32([0xffff_ffff, 1 << 12, 0xffff_ffff, 0xffff_ffff, 0xffff_ffff, 0xffff_ffff])
      0
    end
    state = daemon.send(:capability_state)
    expect(state.last.read_array_of_uint32(6)).to eq([(1 << 12) | (1 << 13), 1 << 12, 0, 0, 0, 0])
    expect(daemon).to receive(:capset).with(*state).and_return(-1)
    expect { daemon.send(:drop_capabilities, state: state) }.to raise_error(SystemCallError, /cannot drop excess capabilities/)
  end

  it 'fails closed if no_new_privs or reading capability state fails' do
    allow(daemon).to receive(:prctl).and_return(-1)
    expect { daemon.send(:capability_state) }.to raise_error(SystemCallError, /cannot set no_new_privs/)
    allow(daemon).to receive(:prctl).and_return(0)
    allow(daemon).to receive(:capget).and_return(-1)
    expect { daemon.send(:capability_state) }.to raise_error(SystemCallError, /cannot read capabilities/)
  end

  it 'refuses writable socket directories and existing symlinks without removing them' do
    allow(daemon).to receive(:capability_state).and_return([])
    expect(daemon).not_to receive(:drop_capabilities)
    Dir.mktmpdir('capd-path-spec-') do |directory|
      path = File.join(directory, 'control.sock')
      File.chmod(0o777, directory)
      expect { daemon.run(uid: Process.uid, interfaces: ['lo'], socket: path) }.to raise_error(ArgumentError, /socket directory/)
      File.chmod(0o700, directory)
      target = File.join(directory, 'target')
      File.write(target, 'untouched')
      File.symlink(target, path)
      expect { daemon.run(uid: Process.uid, interfaces: ['lo'], socket: path) }.to raise_error(Errno::EADDRINUSE)
      expect(File.symlink?(path)).to eq(true)
      expect(File.read(target)).to eq('untouched')
    end
  end

  it 'rejects an unauthorized real Unix peer without reading its payload' do
    server, client = UNIXSocket.pair
    daemon.serve_client(client: server, uid: -1, interfaces: ['lo'], timeout: 0.02)
    expect(JSON.parse(client.gets)).to include('ok' => false, 'error' => 'peer UID denied')
  ensure
    server&.close
    client&.close
  end

  it 'authenticates the peer before allowing status and rejects untyped operations and interfaces' do
    expect(defined?(PWN::Plugins::CapabilityBroker::Daemon)).to be_truthy
    expect(dispatch({ 'operation' => 'status' }, peer_uid: -1)[:error]).to eq('peer UID denied')
    expect(dispatch([])[:error]).to eq('object required')
    expect(dispatch({ 'operation' => 'exec' })[:error]).to eq('operation denied')
    expect(dispatch({ 'operation' => 'raw_send', 'iface' => 'eth0' })[:error]).to eq('interface denied')
    expect(dispatch({ 'operation' => 'status' })).to include(ok: true, backend: 'pwn-capd', interfaces: ['lo'])
  end
end
