# frozen_string_literal: true

require 'open3'

module PWN
  module Plugins
    # This plugin is a simple wrapper around the ps command.
    module PS
      # Supported Method Parameters::
      # proc_list_arr = PWN::Plugins::PS.list

      public_class_method def self.list(opts = {})
        pid = opts[:pid]

        which_os = PWN::Plugins::DetectOS.type

        case which_os
        when :cygwin, :linux
          cmd = 'ps'
          format = 'user,pcpu,pid,ppid,uid,group,gid,cpu,command:1000,pmem'
          params = "-p #{pid} -o #{format}"
          params = "ax -o #{format}" if pid.nil?
        when :freebsd, :netbsd, :openbsd, :osx
          cmd = 'ps'
          format = 'user,pcpu,pid,ppid,uid,group,gid,cpu,command,pmem'
          params = "-p #{pid} -o #{format}"
          params = "ax -o #{format}" if pid.nil?
        else
          raise "Unsupported OS: #{which_os}"
        end

        stdout, _stderr, _status = Open3.capture3(cmd, params)

        proc_list_arr = []
        stdout_arr = stdout.split("\n")
        stdout_arr.each do |line|
          column_len = format.split(',').length
          cmd_idx = column_len - 2
          first_cols = line.split[0..(cmd_idx - 1)]
          cmd = [line.split[cmd_idx..-2].join(' ')]
          pmem = [line.split.last]
          proc_line = first_cols + pmem + cmd
          proc_list_arr.push(proc_line)
        end

        proc_list_arr
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
          proc_list_arr = #{self}.list

          #{self}.authors
        "
      end
    end
  end
end
