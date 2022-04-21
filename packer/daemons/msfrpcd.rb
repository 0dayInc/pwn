#!/usr/bin/env ruby
# frozen_string_literal: true

require 'yaml'
require 'optparse'

opts = {}
OptionParser.new do |options|
  options.banner = "USAGE:
    #{$PROGRAM_NAME} [opts]
  "

  options.on('-aACTION', '--action=ACTION', '<Required - Daemon Action start|reload|stop>') { |a| opts[:action] = a }
end.parse!

if opts.empty?
  puts `#{$PROGRAM_NAME} --help`
  exit 1
end

action = opts[:action].to_s.scrub.to_sym

def start
  if ENV.fetch('PWN_ROOT')
    pwn_root = ENV.fetch('PWN_ROOT')
  elsif Dir.exist?('/pwn')
    pwn_root = '/pwn'
  else
    pwn_root = Dir.pwd
  end

  pwn_provider = ENV.fetch('PWN_PROVIDER') if ENV.fetch('PWN_PROVIDER')
  metasploit_root = '/opt/metasploit-framework-dev'

  msfrpcd_config = YAML.load_file("#{pwn_root}/etc/userland/#{pwn_provider}/metasploit/vagrant.yaml")
  msfrpcd_host = msfrpcd_config['msfrpcd_host'].to_s.scrub.strip.chomp
  msfrpcd_port = msfrpcd_config['port'].to_i
  msfrpcd_user = msfrpcd_config['username'].to_s.scrub.chomp # Don't strip leading space
  msfrpcd_pass = msfrpcd_config['password'].to_s.scrub.chomp # Don't strip leading space
  system("#{metasploit_root}/msfrpcd -a '#{msfrpcd_host}' -p #{msfrpcd_port} -U '#{msfrpcd_user}' -P '#{msfrpcd_pass}'")
  puts 'complete.'
end

def reload
  stop
  sleep 9
  start
end

def stop
  system("ps -ef | grep msfrpcd | grep -v grep | awk '{print $2}' | while read pid; do kill -9 $pid; done")
end

case action
when :start
  start
when :reload
  reload
when :stop
  stop
else
  puts `#{$PROGRAM_NAME} --help`
  exit 1
end
