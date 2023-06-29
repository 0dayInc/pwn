#!/usr/bin/env ruby
# frozen_string_literal: true

require 'yaml'
require 'pwn'

if ENV.fetch('PWN_ROOT')
  pwn_root = ENV.fetch('PWN_ROOT')
elsif Dir.exist?('/pwn')
  pwn_root = '/pwn'
else
  pwn_root = Dir.pwd
end

pwn_provider = ENV.fetch('PWN_PROVIDER') if ENV.fetch('PWN_PROVIDER')
jenkins_userland_config = YAML.load_file("#{pwn_root}/etc/userland/#{pwn_provider}/jenkins/vagrant.yaml")
private_key_path = '/var/lib/jenkins/.ssh/id_rsa-pwn_jenkins'
userland_ssh_keygen_pass = jenkins_userland_config['ssh_keygen_pass']
userland_user = jenkins_userland_config['user']
userland_pass = jenkins_userland_config['pass']
hostname = `hostname`.to_s.chomp.strip.scrub

print 'Creating SSH Key for Userland Jenkins Jobs...'
puts `
  sudo \
    -H \
    -u jenkins \
    /bin/bash \
      --login \
      -c "
        echo y | \
          ssh-keygen \
            -t rsa \
            -b 4096 \
            -C 'jenkins@#{hostname}' \
            -N '#{userland_ssh_keygen_pass}' \
            -f '#{private_key_path}'
      "
`

# TODO: Begin Potential Race Condition of Private SSH Key for Jenkins User
`sudo -H -u jenkins /bin/bash --login -c 'chmod 777 #{File.dirname(private_key_path)} && chmod 644 #{private_key_path}'`

# TODO: Create Jenkins SSH Credentials for all hosts referenced in vagrant.yaml (User-Land Config)
jenkins_obj = PWN::Plugins::Jenkins.connect(
  ip: '127.0.0.1',
  port: 8888,
  username: userland_user,
  api_key: userland_pass
)

if jenkins_userland_config.include?('jenkins_job_credentials') &&
   jenkins_userland_config['jenkins_job_credentials'].any?

  jenkins_userland_config['jenkins_job_credentials'].each do |j_creds_hash|
    ssh_username = j_creds_hash['ssh_username']
    description = j_creds_hash['description']
    credential_id = j_creds_hash['credential_id'].to_s

    if credential_id == ''
      PWN::Plugins::Jenkins.create_ssh_credential(
        jenkins_obj: jenkins_obj,
        username: ssh_username,
        private_key_path: private_key_path,
        key_passphrase: userland_ssh_keygen_pass,
        description: description
      )
    else
      PWN::Plugins::Jenkins.create_ssh_credential(
        jenkins_obj: jenkins_obj,
        username: ssh_username,
        private_key_path: private_key_path,
        key_passphrase: userland_ssh_keygen_pass,
        credential_id: credential_id,
        description: description
      )
    end
  end
end

puts 'The following is the public SSH key created for Jenkins:'
puts `sudo cat /var/lib/jenkins/.ssh/id_rsa-pwn_jenkins.pub`
puts 'If you intend on leveraging User-Land jobs that will connect to remote hosts via SSH'
puts 'please ensure you add the aforementioned public key value to your respective ~/.ssh/authorized_keys file.'
# TODO: End of Potential Race Condition
`sudo -H -u jenkins /bin/bash --login -c 'chmod 600 #{private_key_path} && chmod 700 #{File.dirname(private_key_path)}'`
