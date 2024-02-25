# frozen_string_literal: true

require 'tempfile'

module PWN
  module Plugins
    # This plugin converts images to readable text
    module Assembly
      # Supported Method Parameters::
      # PWN::Plugins::Assembly.opcodes_to_asm(
      #   opcodes: 'required - hex escaped opcode(s) (e.g. "\x90\x90\x90")',
      #   arch: 'optional - objdump -i architecture (defaults to i386)'
      # )

      public_class_method def self.opcodes_to_asm(opts = {})
        opcodes = opts[:opcodes]
        arch = opts[:arch] || 'i386'

        opcodes_tmp = Tempfile.new('pwn_opcodes')
        File.binwrite(opcodes_tmp.path, opcodes)
        `objdump --disassemble-all --target binary --architecture #{arch} #{opcodes_tmp.path}`
      rescue StandardError => e
        raise e
      ensure
        opcodes_tmp.unlink if File.exist?(opcodes_tmp.path)
      end

      # Supported Method Parameters::
      # PWN::Plugins::Assembly.asm_to_opcodes(
      #   asm: 'required - assembly instruction(s) (e.g. 'nop\nnop\nnop\njmp rsp\n)'
      # )

      public_class_method def self.asm_to_opcodes(opts = {})
        asm = opts[:asm]

        asm_code = ".global _start\n_start:\n#{asm}"

        asm_tmp = Tempfile.new('pwn_asm')
        asm_tmp.write(asm_code)
        asm_tmp.close

        asm_tmp_o = "#{asm_tmp.path}.o"
        system('as', '-o', asm_tmp_o, asm_tmp.path)
        `objdump --disassemble-all #{asm_tmp.path}.o`
      rescue StandardError => e
        raise e
      ensure
        files = [asm_tmp.path, asm_tmp_o]
        FileUtils.rm_f(files) if File.exist?(asm_tmp.path)
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
            arch: 'optional - objdump -i architecture (defaults to i386)'
          )

          #{self}.asm_to_opcodes(
            asm: 'required - assembly instruction(s) (e.g. 'jmp rsp')'
          )

          #{self}.authors
        "
      end
    end
  end
end
