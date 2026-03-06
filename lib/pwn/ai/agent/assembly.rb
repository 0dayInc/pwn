# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # This module is an AI agent designed to analyze assembly code, including both opcodes and instructions, for various architectures and endianness. It provides insights into the functionality of the assembly code and can also convert it to C/C++ code when possible.
      module Assembly
        # Supported Method Parameters::
        # ai_analysis = PWN::AI::Agent::Assembly.analyze(
        #   request: 'required - the assembly opcodes or instructions to be analyzed',
        #   type: 'required - :opcodes_to_asm|:asm_to_opcodes - specify the type of analysis to perform',
        #   arch: 'required - name of arch returned from `PWN::Plugins::Assembly.list_supported_archs` (e.g., :i386|:i686|:x86|:x64|:arm|:arm64, etc.)',
        #   endian: 'required - the endianness of the assembly code (e.g., :little|:big)'
        # )

        public_class_method def self.analyze(opts = {})
          request = opts[:request]
          raise 'ERROR: request parameter is required' if request.nil? || request.empty?

          type = opts[:type]
          raise 'ERROR: type parameter is required' if type.nil? || type.empty?

          arch = opts[:arch]
          raise 'ERROR: arch parameter is required' if arch.nil? || arch.empty?

          endian = opts[:endian]
          raise 'ERROR: endian parameter is required' if endian.nil? || endian.empty?

          case type.to_s.downcase.to_sym
          when :opcodes_to_asm
            system_role_content = "Analyze the #{endian} endian #{arch} assembly opcodes below and provide a concise summary of their functionality.  If possible, also convert the assembly to c/c++ code."
          when :asm_to_opcodes
            system_role_content = "Analyze the #{endian} endian #{arch} assembly instructions below and provide a concise summary of their functionality."
          else
            raise "ERROR: Unsupported type parameter value '#{type}'. Supported values are :opcodes_to_asm and :asm_to_opcodes."
          end

          PWN::AI::Introspection.reflect_on(
            system_role_content: system_role_content,
            request: request,
            suppress_pii_warning: true
          )
        rescue StandardError => e
          raise e.backtrace
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
            ai_analysis = PWN::AI::Agent::Assembly.analyze(
              request: 'required - the assembly opcodes or instructions to be analyzed',
              type: 'required - :opcodes_to_asm|:asm_to_opcodes - specify the type of analysis to perform',
              arch: 'required - name of arch returned from `PWN::Plugins::Assembly.list_supported_archs` (e.g., :i386|:i686|:x86|:x64|:arm|:arm64, etc.)',
              endian: 'required - the endianness of the assembly code (e.g., :little|:big)'
            )

            #{self}.authors
          "
        end
      end
    end
  end
end
