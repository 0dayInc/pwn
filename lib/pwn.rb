# frozen_string_literal: true

require 'pwn/version'

# Thank you for choosing the Continuous Security Integrtion Framework!
# Your Source for Source Code Analysis, Vulnerability Scanning, Exploitation,
# & General Security Testing in a Continuous Integration Environment
module PWN
  $stdout.sync = true # < Ensure that all print statements output progress in realtime
  $stdout.flush       # < Ensure that all print statements output progress in realtime
  # TODO: Determine best balance for namespace naming conventions
  autoload :AWS, 'pwn/aws'
  autoload :Banner, 'pwn/banner'
  autoload :FFI, 'pwn/ffi'
  autoload :Plugins, 'pwn/plugins'
  autoload :Reports, 'pwn/reports'
  autoload :SAST, 'pwn/sast'
  autoload :WWW, 'pwn/www'

  # Display a List of Every PWN Module

  public_class_method def self.help
    constants.sort
  end
end
