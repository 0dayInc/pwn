#!/usr/bin/env ruby
# frozen_string_literal: true

print 'Updating BeEF...'
beef_root = '/opt/beef-dev/'
puts `
  sudo /bin/bash \
    --login \
    -c "\
      cd #{beef_root} && \
      rm Gemfile.lock && \
      git pull
    "
`
beef_ruby_version = File.readlines("#{beef_root}/.ruby-version")[0].to_s.scrub.strip.chomp
beef_gemset = File.readlines("#{beef_root}/.ruby-gemset")[0].to_s.scrub.strip.chomp
puts `
  sudo bash \
    --login \
    -c "\
      source /etc/profile.d/rvm.sh; \
      rvm install ruby-#{beef_ruby_version}; \
      rvm use ruby-#{beef_ruby_version}; \
      rvm gemset create #{beef_gemset}; \
      cd #{beef_root}; \
      gem install bundler; \
      bundle install
    "
`
puts 'complete.'
