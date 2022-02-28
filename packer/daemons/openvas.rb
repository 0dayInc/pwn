#!/usr/bin/env ruby
# frozen_string_literal: true

require 'yaml'
require 'optparse'

opts = {}
OptionParser.new do |options|
  options.banner = "USAGE:
    #{$PROGRAM_NAME} [opts]
  "

  options.on('-aACTION', '--action=ACTION', '<Required - Daemon Action start|restart|stop>') { |a| opts[:action] = a }
end.parse!

if opts.empty?
  puts `#{$PROGRAM_NAME} --help`
  exit 1
end

action = opts[:action].to_s.scrub.to_sym

def start
  puts system('/etc/init.d/openvas-manager start')
  puts system('/etc/init.d/openvas-scanner start')
  puts system('/etc/init.d/greenbone-security-assistant start')
end

def restart
  stop
  sleep 3
  start
end

def stop
  puts system('/etc/init.d/greenbone-security-assistant stop')
  puts system('/etc/init.d/openvas-scanner stop')
  puts system('/etc/init.d/openvas-manager stop')
end

case action
when :start
  start
when :restart
  restart
when :stop
  stop
else
  puts `#{$PROGRAM_NAME} --help`
  exit 1
end
