# frozen_string_literal: true

# -*- mode: ruby -*-
# vi: set ft=ruby :
require 'yaml'

API_VERSION = '2'
pwn_root = Pathname.new(__FILE__).realpath.expand_path.parent
vagrant_gui = ENV.fetch('VAGRANT_GUI') if ENV.fetch('VAGRANT_GUI')
pwn_provider = ENV.fetch('PWN_PROVIDER') if ENV.fetch('PWN_PROVIDER')
runtime_userland = 'vagrant_rsync_userland_configs.lst'
template_userland = "#{pwn_root}/vagrant_rsync_userland_template.lst"

if pwn_provider == 'docker'
  docker_container_target = ENV.fetch('DOCKER_CONTAINER_TARGET') if ENV.fetch('DOCKER_CONTAINER_TARGET')
  docker_create_args = [
    '--interactive',
    '--tty'
  ]

  case docker_container_target
  when 'docker_pwn_prototyper'
    docker_container_image = '0dayinc/pwn_prototyper'
    docker_cmd = [
      '--login',
      '-c',
      'echo PWN.help | pwn && pwn'
    ]
  when 'docker_pwn_fuzz_net_app_proto'
    docker_container_image = '0dayinc/pwn_fuzz_net_app_proto'
    docker_cmd = [
      '--login',
      '-c',
      'pwn_fuzz_net_app_proto; bash'
    ]
  when 'docker_pwn_transparent_browser'
    docker_container_image = '0dayinc/pwn_transparent_browser'
    docker_cmd = [
      '--login',
      '-c',
      'echo PWN::Plugins::TransparentBrowser.help | pwn && pwn'
    ]
  when 'docker_pwn_sast'
    docker_container_image = '0dayinc/pwn_sast'
    docker_cmd = [
      '--login',
      '-c',
      'pwn_sast; bash'
    ]
  when 'docker_pwn_www_checkip'
    docker_container_image = '0dayinc/pwn_www_checkip'
    docker_cmd = [
      '--login',
      '-c',
      'pwn_www_checkip -h; bash'
    ]
  else
    raise "Unknown DOCKER_CONTAINER_TARGET: #{docker_container_target}"
  end

  Vagrant.configure(API_VERSION) do |config|
    # config.ssh.username = 'root'
    config.vm.define docker_container_target do
      config.vm.synced_folder('.', '/vagrant', disabled: true)
      config.vm.provider :docker do |d|
        d.name = docker_container_target
        d.image = docker_container_image
        d.create_args = docker_create_args
        d.cmd = docker_cmd
        d.volumes = ['/tmp:/tmp']
        # d.has_ssh = true
      end
    end
  end
else
  puts 'GUI ENABLED.' if vagrant_gui

  Vagrant.configure(API_VERSION) do |config|
    config.vm.box = 'pwn/kali_rolling'
    config.ssh.username = 'admin'

    r = Random.new
    ssh_port = r.rand(1_025...65_535)
    config.vm.network 'forwarded_port', guest: 22, host: ssh_port, id: 'ssh', auto_correct: true

    config.vm.synced_folder(
      '.',
      '/opt/pwn',
      type: 'rsync',
      rsync__args: [
        '--progress',
        "--rsync-path='/usr/bin/sudo rsync'",
        '--archive',
        '--delete',
        '-compress',
        '--recursive',
        '--files-from=vagrant_rsync_third_party.lst',
        '--ignore-missing-args'
      ]
    )

    File.open(runtime_userland, 'w') do |f|
      File.readlines(template_userland).each do |line|
        f.puts "etc/userland/#{pwn_provider}/#{line.chomp}"
      end
    end

    config.vm.synced_folder(
      '.',
      '/opt/pwn',
      type: 'rsync',
      rsync__args: [
        '--progress',
        "--rsync-path='/usr/bin/sudo rsync'",
        '--archive',
        '--delete',
        '-compress',
        '--recursive',
        "--files-from=#{runtime_userland}",
        '--ignore-missing-args'
      ]
    )

    # Load UserLand Configs for Respective Provider
    case pwn_provider
    when 'aws'
      config_path = './etc/userland/aws/vagrant.yaml'
    when 'virtualbox'
      config_path = './etc/userland/virtualbox/vagrant.yaml'
      # config.vm.network('public_network')
    when 'vmware'
      config_path = './etc/userland/vmware/vagrant.yaml'
      # config.vm.network('public_network')
    else
      # This is needed when vagrant ssh is executed
      config_path = ''
    end

    if File.exist?(config_path)
      yaml_config = YAML.load_file(config_path)

      hostname = yaml_config['hostname']
      config.vm.hostname = hostname

      config.vm.provider :virtualbox do |vb, _override|
        if pwn_provider == 'virtualbox'
          vb.gui = false
          vb.gui = true if vagrant_gui == 'true'

          vb.customize ['modifyvm', :id, '--clipboard', 'bidirectional']
          vb.customize ['modifyvm', :id, '--draganddrop', 'bidirectional']
          vb.customize ['modifyvm', :id, '--cpus', yaml_config['cpus']]
          vb.customize ['modifyvm', :id, '--memory', yaml_config['memory']]
          # disk_mb = yaml_config['diskMB']
          # TODO: resize vmdk based on /pwn/etc/userland/vmware/vagrant.yaml
        end
      end

      %i[vmware_fusion vmware_workstation].each do |vmware_provider|
        config.vm.provider vmware_provider do |vm, _override|
          # Workaround until https://github.com/hashicorp/vagrant/issues/10730 is resolved
          vm.ssh_info_public = true
          vm.whitelist_verified = true
          if pwn_provider == 'vmware'
            if vagrant_gui == 'true'
              vm.gui = true
            else
              vm.gui = false
            end
            # vagrant_vmware_license = yaml_config['vagrant_vmware_license']
            vm.vmx['numvcpus'] = yaml_config['cpus']
            vm.vmx['memsize'] = yaml_config['memory']
            vm.vmx['vhv.enable'] = 'true'
            # disk_mb = yaml_config['diskMB']
            # TODO: resize vmdk based on /pwn/etc/userland/vmware/vagrant.yaml
          end
        end
      end

      config.vm.provider :aws do |aws, override|
        if pwn_provider == 'aws'
          override.vm.box = 'dummy'

          # aws_init_script = "#!/bin/bash\necho \"Updating FQDN: #{hostname}\"\ncat /etc/hosts | grep \"#{hostname}\" || sudo sed 's/127.0.0.1/127.0.0.1 #{hostname}/g' -i /etc/hosts\nhostname | grep \"#{hostname}\" || sudo hostname \"#{hostname}\"\nsudo sed -i -e 's/^Defaults.*requiretty/# Defaults requiretty/g' /etc/sudoers\necho 'Defaults:admin !requiretty' >> /etc/sudoers"

          aws.access_key_id = yaml_config['access_key_id']
          aws.secret_access_key = yaml_config['secret_access_key']
          aws.session_token = yaml_config['session_token']
          aws.keypair_name = yaml_config['keypair_name']

          case yaml_config['region']
          when 'us-east-1'
            aws.ami = 'ami-02eb1a4c830533086'
          when 'us-east-2'
            aws.ami = 'ami-0ec0b569397da65f4'
          when 'us-west-1'
            aws.ami = 'ami-0485cc5cdb2c13dd9'
          when 'us-west-2'
            aws.ami = 'ami-0a3b38548723847de'
          else
            raise "Error: #{yaml_config['region']} not supported."
          end

          aws.block_device_mapping = yaml_config['block_device_mapping']
          aws.region = yaml_config['region']
          aws.monitoring = yaml_config['monitoring']
          aws.elastic_ip = yaml_config['elastic_ip']
          aws.associate_public_ip = yaml_config['associate_public_ip']
          aws.private_ip_address = yaml_config['private_ip_address']
          aws.subnet_id = yaml_config['subnet_id']
          aws.instance_type = yaml_config['instance_type']
          aws.iam_instance_profile_name = yaml_config['iam_instance_profile_name']
          aws.security_groups = yaml_config['security_groups']
          aws.tags = yaml_config['tags']
          # Hack for dealing w/ images that require a pty when using sudo and changing hostname
          # aws.user_data = aws_init_script

          override.ssh.username = 'admin'
          override.ssh.private_key_path = yaml_config['ssh_private_key_path']
          override.dns.record_sets = yaml_config['record_sets']
        end
      end

      # Set PWN_PROVIDER for Guest Deployment
      config.vm.provision :shell, inline: "echo \"export PWN_ROOT='#{pwn_root}'\" > /etc/profile.d/pwn_envs.sh"
      config.vm.provision :shell, inline: "echo \"export PWN_PROVIDER='#{pwn_provider}'\" >> /etc/profile.d/pwn_envs.sh"
      # Provision Software Based on UserLand Configurations w/in vagrant_rsync_userland_configs.lst
      # After PWN Box has Booted
      config.vm.provision :shell, path: './vagrant/provisioners/init_env.sh', args: hostname, privileged: false
      config.vm.provision :shell, path: './vagrant/provisioners/kali_customize.rb', args: hostname, privileged: false
      config.vm.provision :shell, path: './vagrant/provisioners/pwn.sh', args: hostname, privileged: false
      config.vm.provision :shell, path: './vagrant/provisioners/postgres.sh', args: hostname, privileged: false
      # AWS EC2 Storage is handled via EBS Volumes
      unless pwn_provider == 'aws'
        config.vm.provision :shell, path: './vagrant/provisioners/userland_fdisk.sh', args: hostname, privileged: false
        config.vm.provision :reload
        config.vm.provision :shell, path: './vagrant/provisioners/userland_lvm.sh', args: hostname, privileged: false
      end
      config.vm.provision :shell, path: './vagrant/provisioners/metasploit.rb', privileged: false
      config.vm.provision :shell, path: './vagrant/provisioners/openvas.sh', privileged: false
      config.vm.provision :shell, path: './vagrant/provisioners/burpsuite_pro.rb', privileged: false
      config.vm.provision :shell, path: './vagrant/provisioners/jenkins.sh', privileged: false
      config.vm.provision :shell, path: './vagrant/provisioners/apache2.sh', privileged: false
      config.vm.provision :shell, path: './vagrant/provisioners/jenkins_ssh-keygen.rb', privileged: false
      config.vm.provision :shell, path: './vagrant/provisioners/post_install.sh', privileged: false
    end
  end
end
File.unlink(runtime_userland)
