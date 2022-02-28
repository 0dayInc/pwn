#!/usr/bin/env ruby
# frozen_string_literal: true

Dir.chdir('/opt')
wpscan_root = '/opt/wpscan-dev/'
`sudo git clone https://github.com/wpscanteam/wpscan.git wpscan-dev`
wpscan_ruby_version = File.readlines("#{wpscan_root}/.ruby-version")[0].to_s.scrub.strip.chomp
wpscan_gemset = File.readlines("#{wpscan_root}/.ruby-gemset")[0].to_s.scrub.strip.chomp
`
  sudo bash \
    --login \
    -c "\
      apt install -y libcurl4-gnutls-dev && \
      source /etc/profile.d/rvm.sh && \
      rvm install ruby-#{wpscan_ruby_version} && \
      rvm use ruby-#{wpscan_ruby_version} && \
      rvm gemset create #{wpscan_gemset} && \
      rvm use ruby-#{wpscan_ruby_version}@#{wpscan_gemset} && \
      cd #{wpscan_root} && \
      gem install bundler && \
      bundle install
    "
`
