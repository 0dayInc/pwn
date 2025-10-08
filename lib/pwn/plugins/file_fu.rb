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

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.recurse_in_dir(
            dir_path: 'optional path to dir defaults to .',
            include_extensions: 'optional - array of file extensions to search for in scan (e.g. ['.js', '.php'])',
            exclude_extensions: 'optional - array of file extensions to exclude from scan (e.g. ['.log', '.txt', '.spec'])'
          ) do |entry|
            puts entry
          end

          #{self}.untar_gz_file(
            tar_gz_file: 'required - path to .tar.gz file',
            destination: 'required - destination folder to save extracted contents'
          )

          #{self}.authors
        "
      end
    end
  end
end
