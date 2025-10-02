# frozen_string_literal: true

require 'pwn/version'

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
  autoload :FFI, 'pwn/ffi'
  autoload :Plugins, 'pwn/plugins'
  autoload :Reports, 'pwn/reports'
  autoload :SAST, 'pwn/sast'
  autoload :WWW, 'pwn/www'
  # TODO: If pwn.yaml is present, attempt to decrypt it, and initialize the YAML config
  # Do this within PWN::Plugins::AuthenticationHelper?

  # Display a List of Every PWN Module

  public_class_method def self.help
    constants.sort
  end
rescue StandardError => e
  puts e.backtrace
  raise e
end
