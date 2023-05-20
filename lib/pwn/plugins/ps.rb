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

        format = 'user,pcpu,pid,ppid,uid,gid,euid,egid,uname,group,args:1000,pmem'

        if pid.nil?
          stdout, _stderr, _status = Open3.capture3(
            'ps',
            'ax',
            '-o',
            format
          )
        else
          stdout, _stderr, _status = Open3.capture3(
            'ps',
            '-p',
            pid.to_s,
            '-o',
            format
          )
        end

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
