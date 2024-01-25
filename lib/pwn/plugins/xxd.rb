# frozen_string_literal: true

module PWN
  module Plugins
    # This module provides the abilty to dump binaries in hex format
    module XXD
      # Supported Method Parameters::
      # PWN::Plugins::XXD.dump(
      #   file: 'required - path to binary file to dump',
      #   hashed: 'optional - return hexdump as hash instead of string (default: false)'
      # )

      public_class_method def self.dump(opts = {})
        file = opts[:file]
        hashed = opts[:hashed] ||= false

        raise ArgumentError, 'file is required' if file.nil?

        raise ArgumentError, 'file does not exist' unless File.exist?(file)

        input = File.binread(file)

        io = StringIO.new
        hashed_hexdump = {}
        res = input.bytes.each_slice(2).each_slice(8).with_index do |row, index|
          fmt_row = format(
            "%<s1>07x0: %<s2>-40s %<s3>-16s\n",
            s1: index,
            s2: row.map { |pair| pair.map { |b| b.to_s(16).rjust(2, '0') }.join }.join(' '),
            s3: row.flat_map { |pair| pair.map { |b| (b >= 32 && b < 127 ? b.chr : '.') } }.flatten.join
          )

          io.write(fmt_row)

          if hashed
            this_key = fmt_row.chars[0..7].join
            if fmt_row.length == 68
              hashed_hexdump[this_key] = {
                hex: fmt_row.chars[10..48].join.split,
                ascii: fmt_row.chars[51..-2].join
              }
            else
              rem_len = fmt_row[10..-1].length
              hex_len = (rem_len / 3) * 2
              ascii_len = rem_len / 3
              hashed_hexdump[this_key] = {
                hex: fmt_row.chars[10..(10 + hex_len)].join.split,
                ascii: fmt_row.chars[(10 + hex_len + 1)..-1].join
              }
            end
          end
        end

        return hashed_hexdump if hashed

        io.string unless hashed
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::XXD.reverse_dump(
      #   hexdump: 'required - hexdump string to reverse dump'
      #   file: 'required - path to binary file to dump'
      # )

      def self.reverse_dump(opts = {})
        hexdump = opts[:hexdump]
        file = opts[:file]
        raise ArgumentError, 'hexdump is required' if hexdump.nil?

        raise ArgumentError, 'output file is required' if file.nil?

        # If hexdump is hashed leveraging the dump method, convert to string
        if hexdump.is_a?(Hash)
          hexdump = hexdump.map do |k, v|
            format(
              "%<s1>07s0: %<s2>-40s %<s3>-16s\n",
              s1: k,
              s2: v[:hex].join(' '),
              s3: v[:ascii]
            )
          end.join
        end

        binary_data = hexdump.lines.map do |line|
          line.split[1..8].map do |hex|
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
            file: 'required - path to binary file to dump',
            hashed: 'optional - return hexdump as hash instead of string (default: false)'
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
