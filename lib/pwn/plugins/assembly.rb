# frozen_string_literal: true

require 'cgi'
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

        raise 'ERROR: opcodes parameter is required.' if opcodes.nil?

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

        # TOOD: Still needs a fix if opcodes are passed in as:
        # '\x90\x90\x90' (not to be confused w/ "\x90\x90\x90")
        # '909090'
        opcodes_orig_len = opcodes.length
        opcodes = opcodes.join(',') if opcodes.is_a?(Array)
        opcodes = CGI.escape(opcodes)
        # puts opcodes.inspect
        # Doesnt work with sommething like: "'ff', 'e4'"
        # known to work with:
        # 'ffe4'
        # 'ff,e4'
        # "ff,e4"
        # ['ff', 'e4']
        # ["ff", "e4"]
        # '\xff\xe4'
        # "\xff\xe4"
        opcodes.delete!('%5Cx') if opcodes.include?('%5Cx')
        opcodes.delete!('%2C') if opcodes.include?('%2C')
        opcodes.delete!('%22') if opcodes.include?('%22')
        opcodes.delete!('%27') if opcodes.include?('%27')
        opcodes.delete!('+') if opcodes.include?('+')
        opcodes.delete!('%') if opcodes.include?('%')
        # puts opcodes.inspect
        opcodes = [opcodes].pack('H*')
        # puts opcodes.inspect

        Metasm::Shellcode.disassemble(arch_obj, opcodes).to_s
      rescue StandardError => e
        raise e
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

        asm_tmp = Tempfile.new('pwn_asm')

        raise 'ERROR: asm parameter is required.' if asm.nil?

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
