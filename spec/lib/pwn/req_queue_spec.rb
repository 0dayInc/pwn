# frozen_string_literal: true

require 'spec_helper'
require 'socket'
require 'tmpdir'

describe 'pwn_debug REQ queue remaining surface' do
  describe PWN::Plugins::ExploitDev do
    it 'catalogs per-arch execve_bin_sh shellcode as opcodes' do
      sc = described_class.shellcode(arch: 'x86_64', kind: 'execve_bin_sh')
      expect(sc.to_s).not_to be_empty
      expect(sc.to_s).not_to eq("\x90")
    end

    it 'one_gadget returns a structured miss when the binary is absent' do
      allow(PWN::Plugins::PreflightChecker).to receive(:bin?).and_call_original
      allow(PWN::Plugins::PreflightChecker).to receive(:bin?).with(name: 'one_gadget').and_return(false)
      row = described_class.one_gadget(path: '/lib/x86_64-linux-gnu/libc.so.6')
      expect(row).to be_a(Hash)
      expect(row[:error].to_s).to match(/one_gadget/i)
    end

    it 'libc_offsets extracts named symbols from an ELF' do
      path = %w[/bin/ls /usr/bin/ls /bin/true /usr/bin/true].find { |p| File.file?(p) }
      skip 'no ELF on host' unless path

      row = described_class.libc_offsets(path: path)
      expect(row).to include(:path)
      expect(row[:symbols]).to be_a(Hash)
    end
  end

  describe PWN::Plugins::GDB do
    it 'core raises without a core path' do
      expect { described_class.core(core: '') }.to raise_error(/core is required/)
    end

    it 'breakpoints includes break commands in the gdb batch' do
      allow(Open3).to receive(:capture3).and_return(['ok', '', instance_double(Process::Status, exitstatus: 0)])
      described_class.breakpoints(binary: '/bin/true', breakpoints: ['main', '*0x401000'])
      expect(Open3).to have_received(:capture3) do |*argv|
        joined = argv.flatten.join(' ')
        expect(joined).to include('break main')
        expect(joined).to include('break *0x401000')
      end
    end
  end

  describe PWN::Plugins::ProcessTube do
    it 'connect uses the same write_line/recvuntil API over TCP' do
      server = TCPServer.new('127.0.0.1', 0)
      port = server.addr[1]
      thr = Thread.new do
        sock = server.accept
        sock.write("banner\n")
        sock.flush
        line = sock.gets
        sock.write("ack #{line}")
        sock.close
      end
      tube = described_class.connect(host: '127.0.0.1', port: port)
      described_class.recvuntil(id: tube[:id], until: "\n", timeout: 2)
      described_class.write_line(id: tube[:id], line: 'hi')
      out = described_class.recvuntil(id: tube[:id], until: 'hi', timeout: 2)
      expect(out).to include('ack')
    ensure
      described_class.close(id: tube[:id]) if tube
      thr&.kill
      server&.close
    end
  end

  describe PWN::Setup do
    it 're profile includes pwndbg, ropper, and rizin' do
      bins = PWN::Setup::PROFILES[:re][:bins]
      expect(bins).to include('pwndbg', 'ropper', 'rizin')
    end
  end

  describe PWN::Plugins::PreflightChecker do
    it 'check includes missing_services' do
      row = described_class.check.find { |r| r[:plugin].to_s.include?('Packet') }
      expect(row).to include(:missing_services)
    end

    it 'service? is false for a missing unix socket' do
      expect(described_class.service?(name: 'no-such-pwn-svc', path: '/tmp/pwn-no-such.sock')).to be false
    end
  end

  describe PWN::Plugins::Sock do
    it 'protocol :raw demands CAP_NET_RAW' do
      allow(PWN::Plugins::PreflightChecker).to receive(:cap_net_raw?).and_return(false)
      expect do
        described_class.connect(target: '127.0.0.1', port: 9, protocol: :raw)
      end.to raise_error(PWN::Plugins::PreflightChecker::MissingCapability)
    end
  end

  describe PWN::Plugins::Nuclei do
    it 'to_findings maps JSONL rows into report-shaped hashes' do
      rows = [{ 'info' => { 'name' => 'xss', 'severity' => 'high' }, 'matched-at' => 'https://x/' }]
      out = described_class.to_findings(rows: rows)
      expect(out.first).to include(:title, :severity, :url)
    end
  end

  describe PWN::Plugins::Fuzz do
    it 'http mutates a request with dictionary payloads' do
      reqs = described_class.http(
        request: "GET /FUZZ HTTP/1.1\r\nHost: x\r\n\r\n",
        dictionary: %w[admin ../]
      )
      expect(reqs.length).to eq(2)
      expect(reqs.first).to include('admin')
    end

    it 'file_format mutates a seed with dictionary blobs' do
      Dir.mktmpdir do |dir|
        seed = File.join(dir, 'seed.bin')
        File.binwrite(seed, 'AAAA')
        out = described_class.file_format(path: seed, dictionary: ["\xff\xff"])
        expect(out).to be_an(Array)
        expect(out.first).to be_a(String)
      end
    end
  end

  describe PWN::Plugins::ArtifactRegistry do
    it 'lists artifacts for a session id' do
      Dir.mktmpdir do |dir|
        stub_const('PWN::Plugins::ArtifactRegistry::ROOT', dir)
        src = File.join(dir, 'loot.txt')
        File.write(src, 'x')
        described_class.register(session_id: 'sess1', path: src, kind: 'loot')
        rows = described_class.list(session_id: 'sess1')
        expect(rows.first[:kind]).to eq('loot')
      end
    end
  end

  describe PWN::Plugins::Frida do
    it 'ssl_pinning_script returns injectable javascript' do
      js = described_class.ssl_pinning_script
      expect(js).to match(/SSL_CTX|TrustManager|pinning/i)
    end
  end

  describe PWN::Plugins::Semgrep do
    it 'responds to scan' do
      expect(described_class).to respond_to(:scan)
    end
  end

  describe PWN::Plugins::ExploitDB do
    it 'responds to search and cve_for_cpe' do
      expect(described_class).to respond_to(:search)
      expect(described_class).to respond_to(:cve_for_cpe)
    end
  end

  describe PWN::Plugins::K8s do
    it 'responds to trivy and kube_hunter' do
      expect(described_class).to respond_to(:trivy)
      expect(described_class).to respond_to(:kube_hunter)
    end
  end
end
