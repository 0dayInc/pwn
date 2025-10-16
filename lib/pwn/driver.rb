# frozen_string_literal: true

require 'optparse'

module PWN
  # Used to consume options passed into PWN drivers and load PWN::Env
  class Driver
    # Add OptionParser options to PWN::Env
    class Parser < OptionParser
      attr_accessor :auto_opts_help,
                    :opts

      def initialize
        super
        @opts = PWN::Env[:driver_opts]
        @auto_opts_help = true

        banner = "USAGE: #{File.basename($PROGRAM_NAME)} [opts]\n"
        on(
          '-YPATH',
          '--pwn_env=PATH',
          '<Optional - PWN::Env YAML file path (Default: ~/.pwn/pwn.yaml)>'
        ) do |o|
          @opts[:pwn_env_path] = o
        end
        on(
          '-ZPATH',
          '--pwn_dec=PATH',
          '<Optional - Out-of-Band YAML file path (Default: ~/.pwn/pwn.decryptor.yaml)>'
        ) do |o|
          @opts[:pwn_dec_path] = o
        end
      end

      def parse!
        super(ARGV, into: @opts)
        # puts @opts

        PWN::Config.refresh_env(
          pwn_env_path: @opts[:pwn_env_path],
          pwn_dec_path: @opts[:pwn_dec_path]
        )

        if @auto_opts_help && @opts.keys.join(' ') == 'pwn_env_path pwn_dec_path'
          puts `#{File.basename($PROGRAM_NAME)} --help`
          exit 1
        end
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
        # Load default driver options into PWN::Env
        opts = PWN::Env[:driver_opts]
        #{self}::Parser.new.parse(&:on).parse!

        # Add more options by passing a block to the parser
        opts = PWN::Env[:driver_opts]
        #{self}::Parser.new do |options|
          # Boolean option
          options.on('-b', '--boolean') do |o|
            opts[:boolean] = o
          end

          # String option
          options.on('-sSTRING', '--string=STRING') do |o|
            opts[:string] = o
          end
        end.parse!

        #{self}.authors
      "
    end
  end
end
