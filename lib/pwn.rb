# frozen_string_literal: true

require 'json'
require 'pwn/json_text'
require 'pwn/runtime_fingerprint'
require 'pwn/version'
require 'yaml'

# json_schemer 2.5.0 uses the syntax class only when `implements` is public.
# regexp_parser 2.13 keeps that writer private, so json_schemer builds an
# instance and then raises NoMethodError on `implements`. A stripped
# `bin/pwn-ai` process does not have that gem; skip the patch there.
begin
  require 'regexp_parser'
  Regexp::Syntax::Base.singleton_class.class_eval { public :implements } if Regexp::Syntax::Base.respond_to?(:implements, true) && !Regexp::Syntax::Base.respond_to?(:implements)
rescue LoadError
  nil
end

# Thank you for choosing the Continuous Security Integrtion Framework!
# Your Source for Source Code Analysis, Vulnerability Scanning, Exploitation,
# & General Security Testing in a Continuous Integration Environment
module PWN
  $stdout.sync = true # < Ensure that all print statements output progress in realtime
  $stdout.flush       # < Ensure that all print statements output progress in realtime
  autoload :AI, 'pwn/ai'
  autoload :AWS, 'pwn/aws'
  autoload :Banner, 'pwn/banner'
  autoload :Bounty, 'pwn/bounty'
  autoload :Blockchain, 'pwn/blockchain'
  autoload :Config, 'pwn/config'
  autoload :Cron, 'pwn/cron'
  autoload :Corpus, 'pwn/corpus'
  autoload :Engagement, 'pwn/engagement'
  autoload :Memory, 'pwn/memory'
  autoload :MemoryIndex, 'pwn/memory_index'
  autoload :Migrate, 'pwn/migrate'
  autoload :Backups, 'pwn/backups'
  autoload :ModuleSkills, 'pwn/module_skills'
  autoload :Sessions, 'pwn/sessions'
  autoload :SessionTrace, 'pwn/session_trace'
  autoload :Redaction, 'pwn/redaction'
  autoload :Setup, 'pwn/setup'
  autoload :Driver, 'pwn/driver'
  autoload :FFI, 'pwn/ffi'
  autoload :Plugins, 'pwn/plugins'
  autoload :Reports, 'pwn/reports'
  autoload :SAST, 'pwn/sast'
  autoload :SDR, 'pwn/sdr'
  autoload :WWW, 'pwn/www'

  # Initialize Options for Drivers

  PWN::Config.init_driver_options

  # Display a List of Every PWN Module

  public_class_method def self.help
    constants.sort
  end

rescue StandardError => e
  puts e.backtrace
  raise e
end
