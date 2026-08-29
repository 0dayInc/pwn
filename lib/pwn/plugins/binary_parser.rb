# frozen_string_literal: true

require 'metasm'

module PWN
  module Plugins
    # ELF/PE/Mach-O headers, sections, symbols, imports/exports, relocations
    # via Metasm loaders.
    module BinaryParser
      public_class_method def self.required_bins
        []
      end

      public_class_method def self.load_exe(opts = {})
        path = opts[:path].to_s
        raise 'ERROR: path is required' if path.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        Metasm::AutoExe.decode_file(path)
      end

      public_class_method def self.info(opts = {})
        exe = load_exe(opts)
        {
          class: exe.class.name,
          cpu: exe.cpu.class.name,
          entrypoint: (exe.optheader.entrypoint if exe.respond_to?(:optheader) && exe.optheader.respond_to?(:entrypoint)),
          format: format_name(exe: exe)
        }
      end

      public_class_method def self.sections(opts = {})
        exe = load_exe(opts)
        Array(exe.sections).map do |sec|
          {
            name: (sec.name if sec.respond_to?(:name)),
            size: (sec.size if sec.respond_to?(:size)),
            virtaddr: (sec.virtaddr if sec.respond_to?(:virtaddr))
          }
        end
      end

      public_class_method def self.symbols(opts = {})
        exe = load_exe(opts)
        return [] unless exe.respond_to?(:symbols)

        Array(exe.symbols).first((opts[:limit] || 200).to_i).map do |sym|
          { name: (sym.name if sym.respond_to?(:name)), value: (sym.value if sym.respond_to?(:value)) }
        end
      end

      public_class_method def self.imports(opts = {})
        exe = load_exe(opts)
        if exe.respond_to?(:imports)
          Array(exe.imports).map(&:to_s)
        else
          symbols(opts).map { |s| s[:name].to_s }.grep(/plt|imp/i).first(100)
        end
      end

      public_class_method def self.exports(opts = {})
        exe = load_exe(opts)
        if exe.respond_to?(:export)
          Array(exe.export&.exports).map { |e| e.respond_to?(:name) ? e.name : e.to_s }
        else
          []
        end
      rescue StandardError
        []
      end

      public_class_method def self.relocations(opts = {})
        exe = load_exe(opts)
        return [] unless exe.respond_to?(:relocations)

        Array(exe.relocations).first((opts[:limit] || 100).to_i).map(&:to_s)
      rescue StandardError
        []
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run load exe and return its result
          #{self}.load_exe(
            path: 'required - filesystem path to read or write'
          )

          # Run info and return its result
          #{self}.info

          # Run sections and return its result
          #{self}.sections

          # Run symbols and return its result
          #{self}.symbols(
            limit: 'optional - limit value consumed by #symbols'
          )

          # Run imports and return its result
          #{self}.imports

          # Run exports and return its result
          #{self}.exports

          # Run relocations and return its result
          #{self}.relocations(
            limit: 'optional - limit value consumed by #relocations'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.format_name(opts = {})
        exe = opts[:exe]
        return 'elf' if exe.class.name.to_s.include?('ELF')
        return 'pe' if exe.class.name.to_s.include?('PE')
        return 'macho' if exe.class.name.to_s.include?('MachO') || exe.class.name.to_s.include?('Mach')

        exe.class.name
      end
    end
  end
end
