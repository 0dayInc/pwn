# frozen_string_literal: true

require 'pry'

module PWN
  module Plugins
    module REPL
      # pwn-asm REPL mode.
      module ASM
        # Register Pry commands for this REPL mode.
        public_class_method def self.add_commands
          Pry::Commands.create_command 'pwn-asm' do
            description 'Initiate pwn.asm shell.'

            def process
              pi = pry_instance
              pi.config.pwn_asm = true

              # Switch to custom multi-line input (SHIFT+ENTER newline, ENTER submit) —
              # same handler pwn-ai uses; restored by `back`.
              pi.config.input = PWNMultiLineInput.new(pi)

              pi.custom_completions = proc do
                [pi.input.line_buffer]
              end

              puts '[*] MULTILINE in pwn-asm: SHIFT+ENTER (or ALT+ENTER, or trailing `\\`) inserts a newline; ENTER submits.'
            end
          end
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):
            0day Inc. <support@0dayinc.com>
          "
        end

        # Display usage for this module.

        public_class_method def self.help
          puts "USAGE:
            # Register the pwn-asm Pry command.
            #{self}.add_commands

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end
      end
    end
  end
end
