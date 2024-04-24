# frozen_string_literal: true

require 'ffi'

module PWN
  module FFI
    # This plugin is a wrapper for the standard I/O functions in libc.
    module Stdio
      extend FFI::Library

      ffi_lib FFI::Library::LIBC

      attach_function(:puts, [:string], :int)
      attach_function(:printf, %i[string varargs], :int, convention: :default)
      attach_function(:scanf, %i[string varargs], :int)

      # Author(s):: 0day Inc. <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.puts string
          #{self}.printf(\"format string\", str, int, etc)

          scanf_buffer = FFI::MemoryPointer.new(:char, 100)
          #{self}.scanf(\"format string\", scanf_buffer)

          #{self}.authors
        "
      end
    end
  end
end
