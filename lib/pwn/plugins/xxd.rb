# frozen_string_literal: true

module PWN
  module Plugins
    # This module provides the abilty to dump binaries in hex format
    module XXD
      # Supported Method Parameters::
      # hexdump = PWN::Plugins::XXD.dump(
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
                hex: fmt_row.chars[10..48].join.delete("\s").scan(/../),
                ascii: fmt_row.chars[51..-2].join
              }
            else
              rem_len = fmt_row[10..-1].length
              hex_len = (rem_len / 3) * 2
              ascii_len = rem_len / 3
              hashed_hexdump[this_key] = {
                hex: fmt_row.chars[10..(10 + hex_len)].join.delete("\s").scan(/../),
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
      # hexdump = PWN::Plugins::XXD.fill_range_w_byte(
      #   hexdump: 'required - hexdump returned from #dump method',
      #   start_addr: 'required - start address to fill with byte',
      #   end_addr: 'required - end address to fill with byte',
      #   byte: 'required - byte to fill range with'
      # )

      def self.fill_range_w_byte(opts = {})
        hexdump = opts[:hexdump]
        start_addr = opts[:start_addr]
        end_addr = opts[:end_addr]
        byte = opts[:byte]

        start_int = start_addr.to_i(16)
        end_int = end_addr.to_i(16)

        hexdump.each do |key, value|
          key_int = key.to_i(16)
          value[:hex] = Array.new(16, byte) if key_int.between?(start_int, end_int)
        end

        hexdump
      end

      # Supported Method Parameters::
      # hex_offset = PWN::Plugins::XXD.calc_addr_offset(
      #   start_addr: 'required - start address to evaluate',
      #   target_addr: 'required - memory address to set breakpoint'
      # )
      # ^^^ Instructions for #{self}.calc_addr_offset:
      # This is useful for calculating address offsets of known functions in debuggers
      # to set breakpoints of instructions that are not known at runtime.
      # 1. Set a breakpoint at main and record its address - this is the start_addr.
      #    For example in r2:
      #    ```
      #    [0x00001050]> db main
      #    [0x00001050]> ood
      #    [0x7fd16122b360]> dc
      #    INFO: hit breakpoint at: 0x562e8547d139
      #    [0x562e8547d139]> db
      #    ```
      # 2. Populate start_addr w/ address (i.e. '0x562e8547d139') of a known function (i.e. main)
      # 3. Step down to the instruction where you want to set a breakpoint. Record its address...
      #    this is the target_addr.
      #    ```
      #    [0x562e8547d139]> v
      #    <step through to the target instruction via F7/F8>
      #    ```
      # 4. Get the hex offset value by calling PWN::Plugins::XXD.calc_addr_offset method
      # 5. Future breakpoints can be calculated by adding the hex offset to the
      #    updated start_addr (which changes every time the binary is executed).
      #    If the offset returned is `0x00000ec2`, a breakpoint for the target
      #    instruction can be set in r2 via:
      #    ```
      #    [0x00001050]> ood
      #    [0x7f1a45bea360]> db main
      #    [0x7f1a45bea360]> db (main)+0x00000ec2
      #    [0x7f1a45bea360]> db
      #    0x558eebd75139 - 0x558eebd7513a 1 --x sw break enabled valid ...
      #    0x558eebd75ffb - 0x558eebd75ffc 1 --x sw break enabled valid ...
      #    [0x7f1a45bea360]> dc
      #    INFO: hit breakpoint at: 0x55ee0a0e5139
      #    [0x55ee0a0e5139]> dc
      #    INFO: hit breakpoint at: 0x5558c3101ffb
      #    [0x5558c3101ffb]> v
      #    <step through via F7, F8, F9, etc. to get to desired instruction>
      #    ```

      def self.calc_addr_offset(opts = {})
        start_addr = opts[:start_addr]
        target_addr = opts[:target_addr]

        format(
          '0x%<s1>08x',
          s1: target_addr.to_i(16) - start_addr.to_i(16)
        )
      end

      # Supported Method Parameters::
      # PWN::Plugins::XXD.reverse_dump(
      #   hexdump: 'required - hexdump returned from #dump method',
      #   file: 'required - path to binary file to dump',
      #   byte_chunks: 'optional - if set, will write n byte chunks of hexdump to multiple files'
      # )

      def self.reverse_dump(opts = {})
        hexdump = opts[:hexdump]
        file = opts[:file]
        byte_chunks = opts[:byte_chunks].to_i

        raise ArgumentError, 'hexdump is required' if hexdump.nil?

        raise ArgumentError, 'output file is required' if file.nil?

        # If hexdump is hashed leveraging the dump method, convert to string
        if hexdump.is_a?(Hash)
          hexdump = hexdump.map do |k, v|
            format(
              "%<s1>s: %<s2>s %<s3>s\n",
              s1: k,
              s2: v[:hex].each_slice(2).map(&:join).join(' '),
              s3: v[:ascii]
            )
          end.join
        end

        puts hexdump

        # Useful for testing which chunk(s)
        # trigger malware detection engines
        if byte_chunks.to_i.positive?
          # Raise error if byte_chunks is not divisible by 16
          raise ArgumentError, 'byte_chunks must be divisible by 16' if (byte_chunks % 16).positive?

          # Raise error if byte_chunks is greater than hexdump size
          raise ArgumentError, 'byte_chunks must be less than hexdump size' if byte_chunks > hexdump.size

          chunks = byte_chunks / 16
          hexdump.lines.each_slice(chunks) do |chunk|
            # File name should append memory address of chunks
            # to make analysis possible
            start_chunk_addr = chunk.first[0..7]
            end_chunk_addr = chunk.last[0..7]
            chunk_file = "#{file}.#{start_chunk_addr}-#{end_chunk_addr}"

            binary_data = chunk.map do |line|
              hex_line = line.split[1..8]
              hex_line = line.split[1..-2] if hex_line.length < 8
              hex_line.map do |hex|
                [hex].pack('H*')
              end.join
            end.join

            File.binwrite(chunk_file, binary_data)
          end
        else
          binary_data = hexdump.lines.map do |line|
            hex_line = line.split[1..8]
            hex_line = line.split[1..-2] if hex_line.length < 8
            hex_line.map do |hex|
              [hex].pack('H*')
            end.join
          end.join

          File.binwrite(file, binary_data)
        end
      rescue StandardError => e
        raise e
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
          hexdump = #{self}.dump(
            file: 'required - path to binary file to dump',
            hashed: 'optional - return hexdump as hash instead of string (default: false)'
          )

          hexdump = #{self}.fill_range_w_byte(
            hexdump: 'required - hexdump returned from #dump method',
            start_addr: 'required - start address to fill with byte',
            end_addr: 'required - end address to fill with byte',
            byte: 'required - byte to fill range with'
          )

          hex_offset = #{self}.calc_addr_offset(
            start_addr: 'required - start address to evaluate',
            target_addr: 'required - memory address to set breakpoint'
          )

          # ^^^ Instructions for #{self}.calc_addr_offset:
          # This is useful for calculating address offsets of known functions in debuggers
          # to set breakpoints of instructions that are not known at runtime.
          # 1. Set a breakpoint at main and record its address - this is the start_addr.
          #    For example in r2:
          #    ```
          #    [0x00001050]> db main
          #    [0x00001050]> ood
          #    [0x7fd16122b360]> dc
          #    INFO: hit breakpoint at: 0x562e8547d139
          #    [0x562e8547d139]> db
          #    ```
          # 2. Populate start_addr w/ address (i.e. '0x562e8547d139') of a known function (i.e. main)
          # 3. Step down to the instruction where you want to set a breakpoint. Record its address...
          #    this is the target_addr.
          #    ```
          #    [0x562e8547d139]> v
          #    <step through to the target instruction via F7/F8>
          #    ```
          # 4. Get the hex offset value by calling #{self}.calc_addr_offset method
          # 5. Future breakpoints can be calculated by adding the hex offset to the
          #    updated start_addr (which changes every time the binary is executed).
          #    If the offset returned is `0x00000ec2`, a breakpoint for the target
          #    instruction can be set in r2 via:
          #    ```
          #    [0x00001050]> ood
          #    [0x7f1a45bea360]> db main
          #    [0x7f1a45bea360]> db (main)+0x00000ec2
          #    [0x7f1a45bea360]> db
          #    0x558eebd75139 - 0x558eebd7513a 1 --x sw break enabled valid ...
          #    0x558eebd75ffb - 0x558eebd75ffc 1 --x sw break enabled valid ...
          #    [0x7f1a45bea360]> dc
          #    INFO: hit breakpoint at: 0x55ee0a0e5139
          #    [0x55ee0a0e5139]> dc
          #    INFO: hit breakpoint at: 0x5558c3101ffb
          #    [0x5558c3101ffb]> v
          #    <step through via F7, F8, F9, etc. to get to desired instruction>
          #    ```

          #{self}.reverse_dump(
            hexdump: 'required - hexdump returned from #dump method',
            file: 'required - path to binary file to dump',
            byte_chunks: 'optional - if set, will write n byte chunks of hexdump to multiple files'
          )

          #{self}.authors
        "
      end
    end
  end
end
