# frozen_string_literal: true

require 'ffi'

PubFFI = ::FFI unless defined?(PubFFI) # rubocop:disable Style/RedundantConstantBase

module PWN
  module FFI
    # This plugin is a wrapper for the standard I/O functions in libc.
    module Stdio
      extend PubFFI::Library

      ffi_lib PubFFI::Library::LIBC

      attach_function(:puts, [:string], :int)
      attach_function(:printf, %i[string varargs], :int, convention: :default)
      attach_function(:scanf, %i[string varargs], :int)

      # Supported Method Parameters::
      # PWN::FFI::Stdio.available?

      public_class_method def self.available?
        true
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        # NB: bare `puts` here would resolve to the FFI-attached libc puts
        # (writes to C stdout, bypasses $stdout capture, flushes at exit).
        $stdout.puts "USAGE:
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
