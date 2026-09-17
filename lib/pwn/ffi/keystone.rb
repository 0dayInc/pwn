# frozen_string_literal: true

require 'ffi'

PubFFI = ::FFI unless defined?(PubFFI) # rubocop:disable Style/RedundantConstantBase

module PWN
  module FFI
    # Thin libkeystone assembler.
    module Keystone
      extend PubFFI::Library

      KS_ARCH_ARM = 1
      KS_ARCH_ARM64 = 2
      KS_ARCH_X86 = 4
      KS_MODE_LITTLE_ENDIAN = 0
      KS_MODE_32 = 4
      KS_MODE_64 = 8

      @load_error = nil
      begin
        ffi_lib %w[keystone libkeystone.so.0 libkeystone.so]
      rescue LoadError => e
        @load_error = e
      end

      class << self
        attr_reader :load_error
      end

      unless @load_error
        attach_function :ks_open, %i[int int pointer], :int
        attach_function :ks_asm, %i[pointer string uint64 pointer pointer pointer], :int
        attach_function :ks_free, [:pointer], :void
        attach_function :ks_close, [:pointer], :int
      end

      public_class_method def self.available?(opts = {})
        opts[:mod]
        load_error.nil?
      end

      public_class_method def self.assemble(opts = {})
        raise 'ERROR: libkeystone not available' unless available?(mod: self)

        asm = opts[:asm].to_s
        raise 'ERROR: asm is required' if asm.empty?

        arch, mode = arch_mode(arch: opts[:arch], endian: opts[:endian])
        ks_ptr = PubFFI::MemoryPointer.new(:pointer)
        raise 'ERROR: ks_open failed' unless ks_open(arch, mode, ks_ptr).zero?

        ks = ks_ptr.read_pointer
        enc = PubFFI::MemoryPointer.new(:pointer)
        size = PubFFI::MemoryPointer.new(:ulong)
        count = PubFFI::MemoryPointer.new(:ulong)
        rc = ks_asm(ks, asm, (opts[:address] || 0).to_i, enc, size, count)
        raise 'ERROR: ks_asm failed' unless rc.zero?

        n = size.read_ulong
        bytes = enc.read_pointer.read_string(n)
        ks_free(enc.read_pointer)
        ks_close(ks)
        { engine: 'keystone', bytes: bytes, hex: bytes.unpack1('H*'), count: count.read_ulong }
      end

      private_class_method def self.arch_mode(opts = {})
        arch = opts[:arch].to_s.downcase
        case arch
        when 'i386', 'i686', 'x86'
          [KS_ARCH_X86, KS_MODE_32]
        when 'aarch64', 'arm64'
          [KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN]
        when /arm/
          [KS_ARCH_ARM, KS_MODE_LITTLE_ENDIAN]
        else
          [KS_ARCH_X86, KS_MODE_64]
        end
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # True when libkeystone is loadable.
          #{self}.available?(
            mod: 'optional - ignored; present so (opts = {}) reads opts['
          )

          # Assemble instructions with Keystone.
          #{self}.assemble(
            asm: 'required - assembly source (one instruction per line)',
            arch: 'optional - x86_64|x86|arm|aarch64',
            endian: 'optional - :little or :big byte order',
            address: 'optional - start address'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
