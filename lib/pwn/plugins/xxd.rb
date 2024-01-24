# frozen_string_literal: true

module PWN
  module Plugins
    # This module provides the abilty to dump binaries in hex format
    module XXD
      # Supported Method Parameters::
      # PWN::Plugins::XXD.dump(
      #   file: 'required - path to binary file to dump'
      # )

      public_class_method def self.dump(opts = {})
        file = opts[:file]

        raise ArgumentError, 'file is required' if file.nil?

        raise ArgumentError, 'file does not exist' unless File.exist?(file)

        input = File.binread(file)

        io = StringIO.new
        res = input.bytes.each_slice(2).each_slice(8).with_index do |row, index|
          io.write(
            format(
              "%<s1>07x0: %<s2>-40s %<s3>-16s\n",
              s1: index,
              s2: row.map { |pair| pair.map { |b| b.to_s(16).rjust(2, '0') }.join }.join(' '),
              s3: row.flat_map { |pair| pair.map { |b| (b >= 32 && b < 127 ? b.chr : '.') } }.flatten.join
            )
          )
        end

        io.string
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::XXD.dump(
      #   hexdump: 'required - hexdump string to reverse dump'
      #   file: 'required - path to binary file to dump'
      # )

      def self.reverse_dump(opts = {})
        hexdump = opts[:hexdump]
        file = opts[:file]
        raise ArgumentError, 'hexdump is required' if hexdump.nil?

        raise ArgumentError, 'output file is required' if file.nil?

        # TODO: fix this block as it is not working as expected
        binary_data = hexdump.lines.map do |line|
          line.split(':')[1].split[0..15].join.split.map do |hex|
            [hex].pack('H*')
          end.join
        end.join

        File.binwrite(file, binary_data)
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
          #{self}.dump(
            file: 'required - path to binary file to dump'
          )

          #{self}.reverse_dump(
            hexdump: 'required - hexdump string to reverse dump',
            file: 'required - path to binary file to dump'
          )

          #{self}.authors
        "
      end
    end
  end
end
