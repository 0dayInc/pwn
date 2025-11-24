# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads FFI modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module FFI
    autoload :Stdio, 'pwn/ffi/stdio'

    # Display a List of Every PWN::FFI Module

    public_class_method def self.help
      constants.sort
    end
  end
end
