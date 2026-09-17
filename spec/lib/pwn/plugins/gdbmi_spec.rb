# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'json'
require 'open3'

describe PWN::Plugins::GDBMI do
  def with_fake_gdb
    Dir.mktmpdir('pwn-gdbmi-') do |dir|
      fake = File.join(dir, 'gdb')
      File.write(fake, <<~RUBY)
        #!/usr/bin/env ruby
        $stdout.sync = true
        $stdin.binmode
        $stdout.puts '=thread-group-added,id="i1"'
        $stdout.puts '(gdb) '
        loop do
          line = $stdin.gets
          break if line.nil?

          cmd = line.to_s.strip
          break if cmd == '-gdb-exit' || cmd == 'quit'

          case cmd
          when /^-break-insert /
            $stdout.puts '^done,bkpt={number="1",type="breakpoint",disp="keep",enabled="y",addr="0x401000",func="main"}'
          when /^-exec-run/, /^-exec-continue/, /^-interpreter-exec console/
            $stdout.puts '^running'
            $stdout.puts '*stopped,reason="signal-received",signal-name="SIGSEGV",frame={addr="0x41414141",func="vuln",offset="0"}'
          when /^-data-list-register-values/
            $stdout.puts '^done,register-values=[{number="16",name="rip",value="0x41414141"},{number="7",name="rsp",value="0x7fffffffe000"}]'
          when /^-data-read-memory-bytes/
            $stdout.puts '^done,memory=[{begin="0x41414141",offset="0",end="0x41414145",contents="41414141"}]'
          when /^-stack-list-frames/
            $stdout.puts '^done,stack=[frame={level="0",addr="0x41414141",func="vuln"},frame={level="1",addr="0x401200",func="main"}]'
          when /si_addr/
            $stdout.puts '^done,value="0x41414141"'
          else
            $stdout.puts '^done'
          end
          $stdout.puts '(gdb) '
        end
      RUBY
      File.chmod(0o755, fake)
      path = File.join(dir, 'fixture.bin')
      File.binwrite(path, 'ELF')
      original = ENV.fetch('PATH', '')
      ENV['PATH'] = "#{dir}:#{original}"
      begin
        yield path
      ensure
        ENV['PATH'] = original
      end
    end
  end

  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'break requires a location' do
    expect { described_class.break(location: '') }.to raise_error(/location|addr/)
  end

  it 'is available as GDBMi and speaks mi3' do
    expect(PWN::Plugins::GDBMi).to eq(described_class)
    with_fake_gdb do |path|
      sid = described_class.open(binary: path)
      expect(described_class.session(session: sid)[:interpreter]).to eq('mi3')
      described_class.close(session: sid)
    end
  end

  it 'rejects injected breakpoint locations before spawning gdb' do
    expect(Open3).not_to receive(:popen2)
    expect { described_class.break(session: 'missing', location: 'main;!id') }.to raise_error(ArgumentError, /location|addr/)
  end

  it 'returns a structured crash report from run_to_crash' do
    with_fake_gdb do |path|
      crash = described_class.run_to_crash(binary: path, stdin: 'AAAA')
      expect(crash).to include(signal: 'SIGSEGV', pc: '0x41414141', fault_addr: '0x41414141')
      expect(crash[:exploitability]).to eq('pc_control')
      expect(crash[:backtrace]).to be_an(Array)
      expect(crash[:registers]).to include('rip' => '0x41414141')
    end
  end

  it 'feeds ExploitDev a cyclic offset from the crash PC' do
    payload = PWN::Plugins::ExploitDev.cyclic(length: 64)
    crash = { signal: 'SIGSEGV', pc: '0x41414141', fault_addr: '0x41414141', exploitability: 'pc_control' }
    row = PWN::Plugins::ExploitDev.from_crash(crash: crash, payload: payload)
    expect(row[:offset]).to be_a(Integer)
    expect(payload[row[:offset], 4]).to eq('AAAA')
  end

  it 'triages a compiled crashing binary to a structured report', :gdb_integration do
    Dir.mktmpdir('pwn-gdb-real-') do |dir|
      source = File.join(dir, 'crash.c')
      path = File.join(dir, 'crash')
      File.write(source, "int main(void) { *(volatile int *)0 = 1; return 0; }\n")
      out, status = Open3.capture2e('cc', '-O0', '-g', '-fno-stack-protector', '-o', path, source)
      expect(status.success?).to eq(true), out
      crash = described_class.run_to_crash(binary: path)
      expect(crash[:signal].to_s).to match(/SEGV/)
      expect(crash[:pc].to_s).to match(/\A0x[0-9a-f]+\z/)
      expect(crash).to include(:fault_addr, :exploitability)
    end
  end
end
