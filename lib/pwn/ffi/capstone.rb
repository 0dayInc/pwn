# frozen_string_literal: true

require 'ffi'

PubFFI = ::FFI unless defined?(PubFFI) # rubocop:disable Style/RedundantConstantBase

module PWN
  module FFI
    # Thin libcapstone disassembler.
    module Capstone
      extend PubFFI::Library

      CS_ARCH_ARM = 0
      CS_ARCH_ARM64 = 1
      CS_ARCH_X86 = 3
      CS_MODE_LITTLE_ENDIAN = 0
      CS_MODE_32 = 4
      CS_MODE_64 = 8

      # Capstone cs_insn layout used by cs_disasm.
      class Insn < PubFFI::Struct
        layout :id, :uint,
               :address, :uint64,
               :size, :ushort,
               :bytes, [:uchar, 24],
               :mnemonic, [:char, 32],
               :op_str, [:char, 160],
               :detail, :pointer
      end

      @load_error = nil
      begin
        ffi_lib %w[capstone libcapstone.so.5 libcapstone.so.4 libcapstone.so]
      rescue LoadError => e
        @load_error = e
      end

      class << self
        attr_reader :load_error
      end

      unless @load_error
        attach_function :cs_open, %i[int int pointer], :int
        attach_function :cs_disasm, %i[size_t pointer size_t uint64 size_t pointer], :size_t
        attach_function :cs_free, %i[pointer size_t], :void
        attach_function :cs_close, [:pointer], :int
      end

      public_class_method def self.available?(opts = {})
        opts[:mod]
        load_error.nil?
      end

      public_class_method def self.disassemble(opts = {})
        raise 'ERROR: libcapstone not available' unless available?(mod: self)

        raw = opts[:bytes] || opts[:opcodes]
        raise 'ERROR: bytes is required' if raw.to_s.empty?

        bytes = raw.to_s.b
        arch, mode = arch_mode(arch: opts[:arch], endian: opts[:endian])
        handle = PubFFI::MemoryPointer.new(:size_t)
        raise 'ERROR: cs_open failed' unless cs_open(arch, mode, handle).zero?

        buf = PubFFI::MemoryPointer.from_string(bytes)
        insn_ptr = PubFFI::MemoryPointer.new(:pointer)
        count = cs_disasm(handle.read_ulong, buf, bytes.bytesize, (opts[:address] || 0).to_i, 0, insn_ptr)
        insns = []
        base = insn_ptr.read_pointer
        count.times do |i|
          insn = Insn.new(base + (i * Insn.size))
          insns << { address: insn[:address], mnemonic: insn[:mnemonic].to_s, op_str: insn[:op_str].to_s, size: insn[:size] }
        end
        cs_free(base, count) unless base.null?
        cs_close(handle)
        { engine: 'capstone', insns: insns, count: count }
      end

      private_class_method def self.arch_mode(opts = {})
        arch = opts[:arch].to_s.downcase
        case arch
        when 'i386', 'i686', 'x86'
          [CS_ARCH_X86, CS_MODE_32]
        when 'aarch64', 'arm64'
          [CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN]
        when /arm/
          [CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN]
        else
          [CS_ARCH_X86, CS_MODE_64]
        end
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # True when libcapstone is loadable.
          #{self}.available?(
            mod: 'optional - ignored; present so (opts = {}) reads opts['
          )

          # Disassemble bytes with Capstone.
          #{self}.disassemble(
            bytes: 'required - raw machine-code bytes',
            opcodes: 'optional - alias for bytes',
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
