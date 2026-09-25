# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

describe PWN::Plugins::BinaryParser do
  it 'should display information for authors' do
    expect(described_class).to respond_to :authors
  end

  it 'should display information for existing help method' do
    expect(described_class).to respond_to :help
  end

  it 'parses an ELF on this host' do
    path = %w[/bin/ls /usr/bin/ls /bin/true /usr/bin/true].find { |p| File.file?(p) }
    skip 'no ELF on PATH' unless path
    info = described_class.info(path: path)
    expect(info[:class].to_s).to match(/ELF|elf/i)
    expect(described_class.sections(path: path)).to be_an(Array)
  end

  it 'triage returns structured JSON fields and caches by sha256' do
    path = %w[/bin/ls /usr/bin/ls /bin/true /usr/bin/true].find { |p| File.file?(p) }
    skip 'no ELF on PATH' unless path
    Dir.mktmpdir do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
      first = described_class.triage(path: path, session_id: 'fixture')
      expect(first).to include(:format, :arch, :protections, :sha256, :sections)
      expect(first[:cached]).to be false
      second = described_class.triage(path: path, session_id: 'fixture')
      expect(second[:cached]).to be true
    end
  end

  it 'surfaces mitigations and attack surface for a stripped ELF in one JSON artifact' do
    Dir.mktmpdir('pwn-triage-') do |dir|
      allow(Dir).to receive(:home).and_return(dir)
      stub_const('PWN::Plugins::ArtifactRegistry::ROOT', File.join(dir, 'artifacts'))
      source = File.join(dir, 'fixture.c')
      path = File.join(dir, 'fixture')
      File.write(source, <<~C)
        #include <stdio.h>
        int main(void) {
          puts("https://example.test/api");
          puts("/var/lib/pwn/keys");
          puts("BEGIN RSA PRIVATE KEY");
          printf("%s %n\\n", "fmt");
          return 0;
        }
      C
      out, status = Open3.capture2e('cc', '-O0', '-g', '-fstack-protector-all', '-o', path, source)
      expect(status.success?).to eq(true), out
      Open3.capture2e('strip', '--strip-all', path)
      row = described_class.triage(path: path, session_id: 'fixture')
      expect(row[:file_type] || row[:format]).to match(/elf/i)
      expect(row[:arch].to_s).not_to be_empty
      expect(row[:linking].to_s).to match(/dynamic|static/)
      expect(row[:protections]).to include(:nx, :pie, :relro, :canary, :cfi)
      expect(row[:protections].values).to all(satisfy { |value| [true, false].include?(value) || value.is_a?(String) })
      expect(row[:stripped]).to eq(true)
      expect(Array(row[:imports]).any? { |name| name.to_s.include?('puts') || name.to_s.include?('printf') || name.to_s.include?('libc') }).to eq(true)
      strings = row[:interesting_strings]
      blob = JSON.generate(strings)
      expect(blob).to include('https://example.test/api')
      expect(blob).to match(%r{/var/lib/pwn/keys})
      expect(blob).to include('%n')
      expect(row[:entropy]).to be_a(Hash)
      expect(row[:entropy].keys).not_to be_empty
      expect(row[:packer]).to include(:packed, :indicators)
      expect(row[:handle].to_s).to match(%r{\Afixture/[0-9a-f]{8}\.bin\z})
      stored = JSON.parse(File.binread(row[:artifact][:path] || File.join(dir, 'artifacts', row[:handle])), symbolize_names: true)
      expect(stored[:sha256]).to eq(row[:sha256])
      expect(stored[:protections]).to include(:canary)
    end
  end

  it 'elf_resolve maps symbols, GOT, and PLT on a compiled ELF' do
    Dir.mktmpdir('pwn-elf-resolve-') do |dir|
      src = File.join(dir, 't.c')
      path = File.join(dir, 't')
      File.write(src, "#include <stdio.h>\n#include <stdlib.h>\nint main(void) { puts(\"hi\"); if (0) system(\"x\"); return 0; }\n")
      out, status = Open3.capture2e('cc', '-O0', '-no-pie', '-o', path, src)
      expect(status.success?).to eq(true), out
      row = described_class.elf_resolve(path: path)
      expect(row[:plt].keys.map(&:to_s)).to include('puts')
      expect(row[:got].keys.map(&:to_s)).to include('puts')
      expect(row[:symbols]['main'] || row[:symbols][:main]).to be_a(Integer)
    end
  end

  it 'elf_resolve points system at the .plt.sec stub, not the next slot' do
    Dir.mktmpdir('pwn-elf-ibt-') do |dir|
      src = File.join(dir, 't.c')
      path = File.join(dir, 't')
      File.write(src, "#include <stdlib.h>\nint main(void) { return system(\"x\"); }\n")
      out, status = Open3.capture2e('cc', '-O0', '-fno-pie', '-no-pie', '-Wl,-z,ibt', '-o', path, src)
      expect(status.success?).to eq(true), out
      expect(File.binread(path)).to include('.plt.sec')
      row = described_class.elf_resolve(path: path)
      dump, dump_status = Open3.capture2('objdump', '-d', path)
      expect(dump_status.success?).to eq(true), dump
      real = dump[/^([0-9a-f]+) <system@plt>:/, 1]
      expect(real).not_to be_nil
      expect(row[:plt]['system']).to eq(real.to_i(16))
    end
  end
end
