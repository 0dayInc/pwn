# frozen_string_literal: true

require 'json'
require 'optparse'
require 'pwn/version'
require 'yaml'

# Thank you for choosing the Continuous Security Integrtion Framework!
# Your Source for Source Code Analysis, Vulnerability Scanning, Exploitation,
# & General Security Testing in a Continuous Integration Environment
module PWN
  $stdout.sync = true # < Ensure that all print statements output progress in realtime
  $stdout.flush       # < Ensure that all print statements output progress in realtime
  autoload :AI, 'pwn/ai'
  autoload :AWS, 'pwn/aws'
  autoload :Banner, 'pwn/banner'
  autoload :Blockchain, 'pwn/blockchain'
  autoload :Config, 'pwn/config'
  autoload :FFI, 'pwn/ffi'
  autoload :Plugins, 'pwn/plugins'
  autoload :Reports, 'pwn/reports'
  autoload :SAST, 'pwn/sast'
  autoload :WWW, 'pwn/www'

  # Display a List of Every PWN Module

  public_class_method def self.help
    constants.sort
  end

  # Initialize PWN configuration file
  # PWN::Env is the constant that stores the configuration data
  PWN::Config.refresh_env
rescue StandardError => e
  puts e.backtrace
  raise e
end
