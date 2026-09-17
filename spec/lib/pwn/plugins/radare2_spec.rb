# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'json'
require 'open3'

describe PWN::Plugins::Radare2 do
  def with_fake_r2
    Dir.mktmpdir('pwn-r2pipe-') do |dir|
      fake = File.join(dir, 'r2')
      File.write(fake, <<~'RUBY')
        #!/usr/bin/env ruby
        $stdout.binmode
        $stdin.binmode
        $stdout.write("\x00")
        $stdout.flush
        loop do
          line = $stdin.gets
          break if line.nil?

          cmd = line.chomp
          break if cmd == 'q'

          out = case cmd
                when 'aaa' then ''
                when 'aflj' then '[{"name":"main","offset":4198400,"size":32}]'
                when /^pdfj/ then '{"name":"main","addr":4198400,"ops":[{"offset":4198400,"opcode":"push rbp","type":"rpush"}]}'
                when /^pdj/ then '[{"offset":4198400,"opcode":"push rbp"}]'
                when /^axtj/ then '[{"from":4198432,"type":"CALL","name":"sym.main"}]'
                when /^wx/, /^s / then ''
                when 's' then '0x401000'
                when /^pxj/ then '[144,144]'
                when 'pd 2 @ main' then "0x00401000  push rbp\n"
                else '{}'
                end
          $stdout.write("#{out}\x00")
          $stdout.flush
        end
      RUBY
      File.chmod(0o755, fake)
      path = File.join(dir, 'fixture.bin')
      File.binwrite(path, 'MZ')
      original = ENV.fetch('PATH', nil)
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

  it 'rejects injected addresses before any r2pipe command is written' do
    expect(Open3).not_to receive(:popen2)
    %i[disasm xrefs_to seek patch_bytes].each do |name|
      expect { described_class.public_send(name, session: 'missing', addr: 'main;!id', n: 8, hex: '90') }.to raise_error(ArgumentError, /addr|address|hex/)
    end
  end

  it 'enumerates functions and returns structured main disassembly from two JSON helpers' do
    with_fake_r2 do |path|
      sid = described_class.open(bin: path)
      functions = described_class.functions(session: sid)
      disasm = described_class.disasm(session: sid, addr: 'main')
      described_class.close(session: sid)
      expect(functions).to be_an(Array)
      expect(functions.first).to include('name' => 'main')
      expect(disasm).to be_a(Hash)
      expect(disasm.fetch('ops')).not_to be_empty
    end
  end

  it 'keeps cmd raw, cmdj parsed, seek JSON, and write-gated patch_bytes' do
    with_fake_r2 do |path|
      sid = described_class.open(bin: path)
      expect(described_class.cmd(session: sid, cmd: 'pd 2 @ main')).to include('push rbp')
      expect(described_class.cmdj(session: sid, cmd: 'afl')).to be_an(Array)
      expect(described_class.xrefs_to(session: sid, addr: 'main')).to be_an(Array)
      expect(described_class.seek(session: sid, addr: 'main')).to include(addr: '0x401000', offset: 0x401000)
      expect { described_class.patch_bytes(session: sid, addr: 'main', hex: '9090') }.to raise_error(ArgumentError, /write/)
      described_class.close(session: sid)
      write = described_class.open(bin: path, write: true)
      expect(described_class.patch_bytes(session: write, addr: 'main', hex: '9090')).to eq([144, 144])
      described_class.close(session: write)
    end
  end

  it 'lets the agent enumerate functions and disassemble main in two structured tool calls' do
    PWN::AI::Agent::Registry.discover(force: true)
    load '/opt/pwn/lib/pwn/ai/agent/tools/radare2.rb'
    with_fake_r2 do |path|
      functions = PWN::AI::Agent::Registry.lookup(name: 'r2_functions').handler.call('bin' => path)
      disasm = PWN::AI::Agent::Registry.lookup(name: 'r2_disasm').handler.call('session' => functions[:session], 'addr' => 'main')
      expect(functions[:command]).to eq('aflj')
      expect(functions[:functions].first).to include('name' => 'main')
      expect(disasm[:command]).to eq('pdfj')
      expect(disasm[:disasm].fetch('ops')).not_to be_empty
    end
  end

  it 'enumerates functions and pulls main disassembly from a compiled binary', :radare2_integration do
    Dir.mktmpdir('pwn-r2-real-') do |dir|
      source = File.join(dir, 'fixture.c')
      path = File.join(dir, 'fixture')
      File.write(source, "int main(void) { return 0; }\n")
      out, status = Open3.capture2e('cc', '-O0', '-g', '-o', path, source)
      expect(status.success?).to eq(true), out
      sid = described_class.open(bin: path)
      functions = described_class.functions(session: sid)
      disasm = described_class.disasm(session: sid, addr: 'main')
      described_class.close(session: sid)
      expect(functions).to be_an(Array)
      expect(functions.any? { |row| row['name'].to_s.include?('main') }).to eq(true)
      expect(disasm).to be_a(Hash)
      expect(disasm['ops']).to be_an(Array)
      expect(disasm['ops']).not_to be_empty
    end
  end
end
