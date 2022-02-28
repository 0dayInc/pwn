#!/usr/bin/env ruby
# frozen_string_literal: true

print 'Updating WordPress Web Vulnerability Scanner (wpscan)...'
Dir.chdir('/opt')
wpscan_root = '/opt/wpscan-dev/'
`sudo rm -rf #{wpscan_root}`
`sudo git clone https://github.com/wpscanteam/wpscan.git wpscan-dev`
wpscan_ruby_version = File.readlines("#{wpscan_root}/.ruby-version")[0].to_s.scrub.strip.chomp
wpscan_gemset = File.readlines("#{wpscan_root}/.ruby-gemset")[0].to_s.scrub.strip.chomp
`sudo bash \
  --login \
  -c "
    source /etc/profile.d/rvm.sh; \
    rvm install ruby-#{wpscan_ruby_version}; \
    rvm use ruby-#{wpscan_ruby_version}; \
    rvm gemset create #{wpscan_gemset}; \
    rvm use ruby-#{wpscan_ruby_version}@#{wpscan_gemset}; \
    cd #{wpscan_root}; \
    gem install bundler; \
    bundle install --without test; \
    rake install
  "
`
puts 'complete.'
