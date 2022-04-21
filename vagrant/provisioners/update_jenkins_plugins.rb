#!/usr/bin/env ruby
# frozen_string_literal: true

require 'yaml'

if ENVfetch('PWN_ROOT')
  pwn_root = ENV.fetch('PWN_ROOT')
elsif Dir.exist?('/pwn')
  pwn_root = '/pwn'
else
  pwn_root = Dir.pwd
end

pwn_provider = ENV.fetch('PWN_PROVIDER') if ENV.fetch('PWN_PROVIDER')
jenkins_userland_config = YAML.load_file("#{pwn_root}/etc/userland/#{pwn_provider}/jenkins/vagrant.yaml")
userland_user = jenkins_userland_config['user']
userland_pass = jenkins_userland_config['pass']

print 'Updating Jenkins Plugins...'
puts `
  /bin/bash \
    --login \
    -c "
      pwn_jenkins_update_plugins \
        -s '127.0.0.1' \
        -d 8888 \
        -U '#{userland_user}' \
        -P '#{userland_pass}'
    "
`
