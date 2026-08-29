# frozen_string_literal: true

require 'fileutils'
require 'shellwords'
require 'rubygems/package'
require 'zlib'

module PWN
  module Plugins
    # This plugin is primarily used for interacting with files and directories
    # in addition to the capabilities already built within the File and FileUtils
    # built-in ruby classes (e.g. contains an easy to use recursion method that
    # uses yield to interact with each entry on the fly).
    module FileFu
      # Supported Method Parameters::
      # PWN::Plugins::FileFu.recurse_in_dir(
      #   dir_path: 'optional path to dir defaults to .',
      #   include_extensions: 'optional - array of file extensions to search for in scan (e.g. ['.js', '.php'])',
      #   exclude_extensions: 'optional - array of file extensions to exclude from scan (e.g. ['.log', '.txt', '.spec'])'
      # )

      public_class_method def self.recurse_in_dir(opts = {})
        dir_path = opts[:dir_path] ||= '.'
        dir_path = dir_path.to_s.scrub unless dir_path.is_a?(String)
        raise "PWN Error: Invalid Directory #{dir_path}" unless Dir.exist?(dir_path)

        include_extensions = opts[:include_extensions] ||= []
        exclude_extensions = opts[:exclude_extensions] ||= []

        previous_dir = Dir.pwd
        Dir.chdir(dir_path)
        # Execute this like this:
        # recurse_in_dir(:dir_path => 'path to dir') {|entry| puts entry}
        Dir.glob('./**/*').each do |entry|
          next if exclude_extensions.include?(File.extname(entry))

          next unless include_extensions.empty? || include_extensions.include?(File.extname(entry))

          yield Shellwords.escape(entry)
        end
      rescue StandardError => e
        raise e
      ensure
        Dir.chdir(previous_dir) if Dir.exist?(previous_dir)
      end

      # Supported Method Parameters::
      # PWN::Plugins::FileFu.untar_gz_file(
      #   tar_gz_file: 'required - path to .tar.gz file',
      #   destination: 'required - destination folder to save extracted contents'
      # )

      public_class_method def self.untar_gz_file(opts = {})
        tar_gz_file = opts[:tar_gz_file].to_s.scrub if File.exist?(opts[:tar_gz_file].to_s.scrub)
        destination = opts[:destination].to_s.scrub if Dir.exist?(File.dirname(tar_gz_file))
        puts `tar -xzvf #{tar_gz_file} -C #{destination}`

        nil
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters:
      # PWN::Plugins::FileFu.shift_file_up(
      #   path:       'required - path to file to shift up',
      #   bytes:      'required - number of bytes to shift up (remove from beginning)',
      #   buffer_size: 'optional - buffer size to use when shifting (default: 256KB)'
      # )

      public_class_method def self.shift_file_up(opts = {})
        path = opts[:path].to_s.scrub
        raise "PWN Error: File #{path} does not exist" unless File.exist?(path)

        bytes = opts[:bytes].to_i
        raise 'PWN Error: bytes must be greater than or equal to 0' unless bytes >= 0

        # Default buffer size = 256 KiB — good general-purpose value
        buffer_size = (opts[:buffer_size] || (256 * 1024)).to_i
        raise 'PWN Error: buffer_size must be greater than 0' unless buffer_size.positive?

        # 'r+b' = read/write + binary mode
        File.open(path, 'r+b') do |f|
          size = f.stat.size
          break if bytes >= size

          read_pos  = bytes
          write_pos = 0
          buffer    = String.new(capacity: buffer_size)

          while read_pos < size
            f.seek(read_pos)
            chunk = f.read(buffer_size, buffer) or break

            bytes_read = chunk.bytesize

            f.seek(write_pos)
            f.write(buffer.byteslice(0, bytes_read))

            read_pos  += bytes_read
            write_pos += bytes_read
          end

          f.truncate(size - bytes)
        end
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
          # Run recurse in dir and return its result
          #{self}.recurse_in_dir(
            dir_path: 'optional - optional path to dir defaults to .',
            include_extensions: 'optional - array of file extensions to search for in scan (e.g. [.js, .php])',
            exclude_extensions: 'optional - array of file extensions to exclude from scan (e.g. [.log, .txt, .spec])'
          )

          # Run untar gz file and return its result
          #{self}.untar_gz_file(
            tar_gz_file: 'required - path to .tar.gz file',
            destination: 'required - destination folder to save extracted contents'
          )

          # Run shift file up and return its result
          #{self}.shift_file_up(
            path: 'required - path to file to shift up',
            bytes: 'required - number of bytes to shift up (remove from beginning)',
            buffer_size: 'optional - buffer size to use when shifting (default: 256KB)'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
