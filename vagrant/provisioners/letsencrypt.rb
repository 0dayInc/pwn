#!/usr/bin/env ruby
# frozen_string_literal: true

require 'yaml'

print "Installing Let's Encrypt **************************************************************"
if ENV.fetch('PWN_ROOT')
  pwn_root = ENV.fetch('PWN_ROOT')
elsif Dir.exist?('/pwn')
  pwn_root = '/pwn'
else
  pwn_root = Dir.pwd
end

pwn_provider = ENV.fetch('PWN_PROVIDER') if ENV.fetch('PWN_PROVIDER')
letsencrypt_git = 'https://github.com/letsencrypt/letsencrypt'
letsencrypt_root = '/opt/letsencrypt-git'
letsencrypt_yaml = YAML.load_file("#{pwn_root}/etc/userland/#{pwn_provider}/letsencrypt/vagrant.yaml")
letsencrypt_domains = letsencrypt_yaml['domains']
letsencrypt_email = letsencrypt_yaml['email'].to_s.scrub.strip.chomp

letsencrypt_flags = '--apache'
letsencrypt_domains.each { |domain| letsencrypt_flags = "#{letsencrypt_flags} -d #{domain}" }
letsencrypt_flags = "#{letsencrypt_flags} --non-interactive --agree-tos --text --email #{letsencrypt_email}"

system(
  "sudo -i /bin/bash \
    --login \
    -c \"
      git clone #{letsencrypt_git} #{letsencrypt_root} && \
      cd #{letsencrypt_root} && \
      ./letsencrypt-auto-source/letsencrypt-auto #{letsencrypt_flags}
    \"
  "
)
