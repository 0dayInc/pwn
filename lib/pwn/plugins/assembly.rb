# frozen_string_literal: true

require 'tempfile'

module PWN
  module Plugins
    # This plugin converts images to readable text
    module Assembly
      # Supported Method Parameters::
      # PWN::Plugins::Assembly.opcode_to_asm(
      #   opcodes: 'required - hex escaped opcode(s) (e.g. '\x90\x90\x90')',
      #   arch: 'optional - architecture (defaults to PWN::Plugins::DetectOS.arch)'
      # )

      public_class_method def self.opcodes_to_asm(opts = {})
        opcodes = opts[:opcodes]
        arch = opts[:arch] ||= PWN::Plugins::DetectOS.arch

        opcodes_tmp = Tempfile.new('pwn_opcodes')
        File.binwrite(opcodes_tmp.path, opcodes)
        asm = `objdump -M intel -b binary -D #{opcodes_tmp.path}`
        opcodes_tmp.unlink

        asm
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Assembly.asm_to_opcode(
      #   asm: 'required - assembly code(s) (e.g. 'nop\nnop\nnop\njmp rsp\n)',
      #   arch: 'optional - architecture (defaults to PWN::Plugins::DetectOS.arch)'
      # )

      public_class_method def self.asm_to_opcode(opts = {})
        asm = opts[:asm]
        arch = opts[:arch] ||= PWN::Plugins::DetectOS.arch

        asm_code = ".global _start\n_start:\n#{asm}"

        asm_tmp = Tempfile.new('pwn_asm')
        asm_tmp.write(asm_code)
        asm_tmp.close

        system('as', '-o', "#{asm_tmp.path}.o", asm_tmp.path)
        opcodes = `objdump -d #{asm_tmp.path}.o`
        asm_tmp.unlink

        opcodes
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
          #{self}.opcode_to_asm(
            opcodes: 'required - hex escaped opcode(s) (e.g. '\\x90\\x90\\x90')',
            arch: 'optional - architecture (defaults to PWN::Plugins::DetectOS.arch)'
          )

          #{self}.asm_to_opcode(
            asm: 'required - assembly code(s) (e.g. 'jmp rsp')',
            arch: 'optional - architecture (defaults to PWN::Plugins::DetectOS.arch)'
          )

          #{self}.authors
        "
      end
    end
  end
end
