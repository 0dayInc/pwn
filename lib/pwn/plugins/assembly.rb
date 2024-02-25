# frozen_string_literal: true

require 'tempfile'

module PWN
  module Plugins
    # This plugin converts images to readable text
    module Assembly
      # Supported Method Parameters::
      # PWN::Plugins::Assembly.opcode_to_asm(
      #   opcodes: 'required - hex escaped opcode(s) (e.g. '\x90\x90\x90')'
      # )

      public_class_method def self.opcodes_to_asm(opts = {})
        opcodes = opts[:opcodes]

        opcodes_tmp = Tempfile.new('pwn_opcodes')
        File.binwrite(opcodes_tmp.path, opcodes)
        `objdump -D #{opcodes_tmp.path}`
      rescue StandardError => e
        raise e
      ensure
        opcodes_tmp.unlink if File.exist?(opcodes_tmp.path)
      end

      # Supported Method Parameters::
      # PWN::Plugins::Assembly.asm_to_opcode(
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
        `objdump -D #{asm_tmp.path}.o`
      rescue StandardError => e
        raise e
      ensure
        FileUtils.rm_f("#{asm_tmp.path}*") if File.exist?(asm_tmp.path)
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
            opcodes: 'required - hex escaped opcode(s) (e.g. '\\x90\\x90\\x90')'
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
