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
      #   opcodes_always_string_obj: 'optional - always interpret opcodes passed in as a string object (defaults to false)',
      #   arch: 'optional - architecture returned from objdump --info (defaults to PWN::Plugins::DetectOS.arch)',
      #   endian: 'optional - endianess :big|:little (defaults to current system endianess)'
      # )

      public_class_method def self.opcodes_to_asm(opts = {})
        opcodes = opts[:opcodes]
        opcodes_always_string_obj = opts[:opcodes_always_string_obj] ||= false
        arch = opts[:arch] ||= PWN::Plugins::DetectOS.arch
        endian = opts[:endian]

        if opts[:endian].nil? && [1].pack('I') == [1].pack('N')
          endian = :big
        else
          endian = :little
        end

        endian = endian.to_sym if opts[:endian]

        raise 'ERROR: opcodes parameter is required.' if opcodes.nil?

        case arch.to_s.downcase
        when 'i386', 'i686', 'x86'
          arch_obj = Metasm::Ia32.new(endian)
        when 'amd64', 'x86_64'
          arch_obj = Metasm::X86_64.new(endian)
        when 'arc'
          arch_obj = Metasm::ARC.new(endian)
        when 'armv4l', 'armv4b', 'armv5l', 'armv5b', 'armv6l', 'armv6b', 'armv7b', 'armv7l', 'arm', 'armhf'
          arch_obj = Metasm::ARM.new(endian)
        when 'aarch64', 'arm64'
          arch_obj = Metasm::ARM64.new(endian)
        when 'bpf'
          arch_obj = Metasm::BPF.new(endian)
        when 'cy16'
          arch_obj = Metasm::CY16.new(endian)
        when 'dalvik'
          arch_obj = Metasm::Dalvik.new(endian)
        when 'ebpf'
          arch_obj = Metasm::EBPF.new(endian)
        when 'mcs51'
          arch_obj = Metasm::MCS51.new(endian)
        when 'mips'
          arch_obj = Metasm::MIPS.new(endian)
        when 'mips64'
          arch_obj = Metasm::MIPS64.new(endian)
        when 'msp430'
          arch_obj = Metasm::MSP430.new(endian)
        when 'openrisc'
          arch_obj = Metasm::OpenRisc.new(endian)
        when 'ppc'
          arch_obj = Metasm::PPC.new(endian)
        when 'sh4'
          arch_obj = Metasm::SH4.new(endian)
        when 'st20'
          arch_obj = Metasm::ST20.new(endian)
        when 'webasm'
          arch_obj = Metasm::WebAsm.new(endian)
        when 'z80'
          arch_obj = Metasm::Z80.new(endian)
        else
          raise "Unsupported architecture: #{arch}"
        end

        # TOOD: Still needs a fix if opcodes are passed in as:
        # '\x90\x90\x90' (not to be confused w/ "\x90\x90\x90")
        # '909090'
        opcodes_orig_len = opcodes.length
        opcodes = opcodes.join(',') if opcodes.is_a?(Array)
        # puts opcodes.inspect
        opcodes = CGI.escape(opcodes)
        # puts opcodes.inspect
        # known to work (when method is called directly) with:
        # 'ffe4'
        # 'ff,e4'
        # 'ff e4'
        # "ff,e4"
        # "ff e4"
        # ['ff', 'e4']
        # ["ff", "e4"]
        # '\xff\xe4'
        # "\xff\xe4"
        # "'ff', 'e4'"
        # '"ff", "e4"'
        # only known to work in pwn REPL driver with:
        # ffe4
        # ff e4
        # puts opcodes.inspect
        #  More stripping if passed in via pwn REPL driver
        # if opcodes_always_string_obj
        # end

        opcodes.delete!('%5B')
        opcodes.delete!('%5D')
        opcodes.delete!('%5Cx')
        opcodes.delete!('%2C')
        opcodes.delete!('%22')
        opcodes.delete!('%27')
        opcodes.delete!('+')
        opcodes.delete!('%')

        # puts opcodes.inspect
        opcodes = [opcodes].pack('H*')
        # puts opcodes.inspect

        Metasm::Shellcode.disassemble(arch_obj, opcodes).to_s.squeeze("\n")
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Assembly.asm_to_opcodes(
      #   asm: 'required - assembly instruction(s) (e.g. 'nop\nnop\nnop\njmp rsp\n)',
      #   arch: 'optional - architecture returned from objdump --info (defaults to PWN::Plugins::DetectOS.arch)',
      #   endian: 'optional - endianess :big|:little (defaults to current system endianess)'
      # )

      public_class_method def self.asm_to_opcodes(opts = {})
        asm = opts[:asm]
        arch = opts[:arch] ||= PWN::Plugins::DetectOS.arch
        endian = opts[:endian] ||= :little

        if opts[:endian].nil? && [1].pack('I') == [1].pack('N')
          endian = :big
        else
          endian = :little
        end

        endian = endian.to_sym if opts[:endian]

        asm_tmp = Tempfile.new('pwn_asm')

        raise 'ERROR: asm parameter is required.' if asm.nil?

        case arch.to_s.downcase
        when 'i386', 'i686', 'x86'
          arch_obj = Metasm::Ia32.new(endian)
        when 'amd64', 'x86_64'
          arch_obj = Metasm::X86_64.new(endian)
        when 'arc'
          arch_obj = Metasm::ARC.new(endian)
        when 'armv4l', 'armv4b', 'armv5l', 'armv5b', 'armv6l', 'armv6b', 'armv7b', 'armv7l', 'arm', 'armhf'
          arch_obj = Metasm::ARM.new(endian)
        when 'aarch64', 'arm64'
          arch_obj = Metasm::ARM64.new(endian)
        when 'bpf'
          arch_obj = Metasm::BPF.new(endian)
        when 'cy16'
          arch_obj = Metasm::CY16.new(endian)
        when 'dalvik'
          arch_obj = Metasm::Dalvik.new(endian)
        when 'ebpf'
          arch_obj = Metasm::EBPF.new(endian)
        when 'mcs51'
          arch_obj = Metasm::MCS51.new(endian)
        when 'mips'
          arch_obj = Metasm::MIPS.new(endian)
        when 'mips64'
          arch_obj = Metasm::MIPS64.new(endian)
        when 'msp430'
          arch_obj = Metasm::MSP430.new(endian)
        when 'openrisc'
          arch_obj = Metasm::OpenRisc.new(endian)
        when 'ppc'
          arch_obj = Metasm::PPC.new(endian)
        when 'sh4'
          arch_obj = Metasm::SH4.new(endian)
        when 'st20'
          arch_obj = Metasm::ST20.new(endian)
        when 'webasm'
          arch_obj = Metasm::WebAsm.new(endian)
        when 'z80'
          arch_obj = Metasm::Z80.new(endian)
        else
          raise "Unsupported architecture: #{arch}"
        end

        opcodes = Metasm::Shellcode.assemble(arch_obj, asm).encode_string
        hex_encoded_opcodes = opcodes.bytes.map { |b| format('\x%02x', b) }.join

        "\n#{hex_encoded_opcodes}\n"
      rescue Metasm::ParseError
        puts "Invalid assembly instruction(s) provided:\n#{asm}"
        # Should we try to call opcode_to_asm here or just raise the error?
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Assembly.list_archs

      public_class_method def self.list_supported_archs
        [
          { name: 'i386', endian: 'little' },
          { name: 'i686', endian: 'little' },
          { name: 'x86', endian: 'little' },
          { name: 'amd64', endian: 'little' },
          { name: 'x86_64', endian: 'little' },
          { name: 'arc', endian: 'little' },
          { name: 'armv4l', endian: 'little' },
          { name: 'armv4b', endian: 'big' },
          { name: 'armv5l', endian: 'little' },
          { name: 'armv5b', endian: 'big' },
          { name: 'armv6l', endian: 'little' },
          { name: 'armv6b', endian: 'big' },
          { name: 'armv7b', endian: 'big' },
          { name: 'armv7l', endian: 'little' },
          { name: 'arm', endian: 'little' },
          { name: 'armhf', endian: 'little' },
          { name: 'aarch64', endian: 'little' },
          { name: 'arm64', endian: 'little' },
          { name: 'bpf', endian: 'little' },
          { name: 'cy16', endian: 'little' },
          { name: 'dalvik', endian: 'little' },
          { name: 'ebpf', endian: 'little' },
          { name: 'mcs51', endian: 'little' },
          { name: 'mips', endian: 'little' },
          { name: 'mips64', endian: 'little' },
          { name: 'msp430', endian: 'little' },
          { name: 'openrisc', endian: 'little' },
          { name: 'ppc', endian: 'little' },
          { name: 'sh4', endian: 'little' },
          { name: 'st20', endian: 'little' },
          { name: 'webasm', endian: 'little' },
          { name: 'z80', endian: 'little' }
        ]
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.opcodes_to_asm(
            opcodes: 'required - hex escaped opcode(s) (e.g. \"\\x90\\x90\\x90\")',
            opcodes_always_string_obj: 'optional - always interpret opcodes passed in as a string object (defaults to false)',
            arch: 'optional - architecture returned from objdump --info (defaults to PWN::Plugins::DetectOS.arch)',
            endian: 'optional - endianess :big|:little (defaults to system endianess)'
          )

          #{self}.asm_to_opcodes(
            asm: 'required - assembly instruction(s) (e.g. 'nop\nnop\nnop\njmp rsp\n)',
            arch: 'optional - architecture returned from objdump --info (defaults to PWN::Plugins::DetectOS.arch)',
            endian: 'optional - endianess :big|:little (defaults to system endianess)'
          )

          #{self}.list_supported_archs

          #{self}.authors
        "
      end
    end
  end
end
