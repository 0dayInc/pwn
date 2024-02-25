# frozen_string_literal: true

require 'metasm'
require 'tempfile'

module PWN
  module Plugins
    # This plugin converts images to readable text
    module Assembly
      # Supported Method Parameters::
      # PWN::Plugins::Assembly.opcodes_to_asm(
      #   opcodes: 'required - hex escaped opcode(s) (e.g. "\x90\x90\x90")',
      #   arch: 'optional - architecture returned from objdump --info (defaults to PWN::Plugins::DetectOS.arch)',
      #   endian: 'optional - endianess (defaults to :little)'
      # )

      public_class_method def self.opcodes_to_asm(opts = {})
        opcodes = opts[:opcodes]
        arch = opts[:arch] ||= PWN::Plugins::DetectOS.arch
        endian = opts[:endian] ||= :little

        raise "ERROR: opcodes parameter is required." if opcodes.nil?

        case arch
        when 'amd64', 'i386', 'i686', 'x86', 'x86_64'
          arch = 'i386'
        when 'armv4l', 'armv4b', 'armv5l', 'armv5b', 'armv6l', 'armv6b', 'armv7b', 'armv7l', 'arm', 'armhf'
          arch = 'arm'
        when 'aarch64', 'arm64'
          arch = 'aarch64'
        else
          raise "Unsupported architecture: #{arch}"
        end

        # If opcodes appear to be '"90", "90", "90"' then convert to "\x90\x90\x90"
        opcodes = opcodes.split(',').map { |x| format('\x%02x', x.gsub('"', '').to_i(16)) }.join if opcodes.include?('"') && opcodes.include?(',')

        # If opcodes appear to be '90 90 90' then convert to "\x90\x90\x90"
        opcodes = opcodes.split.map { |x| format('\x%02x', x.to_i(16)) }.join if opcodes.include?(' ')

        # If opcodes appear to be '909090' then convert to "\x90\x90\x90"
        opcodes = opcodes.chars.each_slice(2).map(&:join).map { |x| format('\x%02x', x.to_i(16)) }.join if opcodes.length.even?

        pwn_asm_tmp = Tempfile.new('pwn_asm')
        File.binwrite(pwn_asm_tmp.path, opcodes)
        `objdump -D -b binary -m #{arch} -M intel --endian #{endian} #{pwn_asm_tmp.path}`
      rescue StandardError => e
        raise e
      ensure
        tmp_file = [pwn_asm_tmp.path]
        FileUtils.rm_f(tmp_file) if File.exist?(pwn_asm_tmp.path)
      end

      # Supported Method Parameters::
      # PWN::Plugins::Assembly.asm_to_opcodes(
      #   asm: 'required - assembly instruction(s) (e.g. 'nop\nnop\nnop\njmp rsp\n)',
      #   arch: 'optional - architecture returned from objdump --info (defaults to PWN::Plugins::DetectOS.arch)',
      #   endian: 'optional - endianess (defaults to :little)'
      # )

      public_class_method def self.asm_to_opcodes(opts = {})
        asm = opts[:asm]
        arch = opts[:arch] ||= PWN::Plugins::DetectOS.arch
        endian = opts[:endian] ||= :little

        raise "ERROR: asm parameter is required." if asm.nil?

        case arch
        when 'i386', 'i686', 'x86'
          arch_obj = Metasm::Ia32.new(endian)
        when 'amd64', 'x86_64'
          arch_obj = Metasm::X86_64.new(endian)
        when 'armv4l', 'armv4b', 'armv5l', 'armv5b', 'armv6l', 'armv6b', 'armv7b', 'armv7l', 'arm', 'armhf'
          arch_obj = Metasm::ARM.new(endian)
        when 'aarch64', 'arm64'
          arch_obj = Metasm::ARM64.new(endian)
        else
          raise "Unsupported architecture: #{arch}"
        end

        raise "ERROR: #{as_bin} not found.  Choose a different arch parameter." unless File.exist?(as_bin)

        Metasm::Shellcode.assemble(arch_obj, asm).encode_string.bytes.map { |b| format('\x%02x', b) }.join
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.opcodes_to_asm(
            opcodes: 'required - hex escaped opcode(s) (e.g. \"\\x90\\x90\\x90\")',
            arch: 'optional - architecture returned from objdump --info (defaults to PWN::Plugins::DetectOS.arch)',
            endian: 'optional - endianess (defaults to :little)'
          )

          #{self}.asm_to_opcodes(
            asm: 'required - assembly instruction(s) (e.g. 'nop\nnop\nnop\njmp rsp\n)',
            arch: 'optional - architecture returned from objdump --info (defaults to PWN::Plugins::DetectOS.arch)',
            endian: 'optional - endianess (defaults to :little)'
          )

          #{self}.authors
        "
      end
    end
  end
end
