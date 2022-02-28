#!/bin/bash
# Update user/pass based on UserLand Configs
if [[ $PWN_ROOT == '' ]]; then
  if [[ ! -d '/pwn' ]]; then
    pwn_root=$(pwd)
  else
    pwn_root='/pwn'
  fi
else
  pwn_root="${PWN_ROOT}"
fi

pwn_provider=`echo $PWN_PROVIDER`
openvas_vagrant_yaml="${pwn_root}/etc/userland/${pwn_provider}/openvas/vagrant.yaml"
apache_vagrant_yaml="${pwn_root}/etc/userland/${pwn_provider}/apache2/vagrant.yaml"
user=`ruby -e "require 'yaml'; print YAML.load_file('${openvas_vagrant_yaml}')['user']"`
pass=`ruby -e "require 'yaml'; print YAML.load_file('${openvas_vagrant_yaml}')['pass']"`
fqdn=`ruby -e "require 'yaml'; print YAML.load_file('${apache_vagrant_yaml}')['common_name_fqdn']"`
sudo /bin/bash --login -c "openvasmd --create-user ${user}"
sudo /bin/bash --login -c "openvasmd --user=${user} --new-password=${pass}"
sudo sed -i "9s/.*/ExecStart=\/usr\/sbin\/gsad --foreground --listen=127\.0\.0\.1 --port=9392 --mlisten=127\.0\.0\.1 --mport=9390 --http-only --no-redirect --allow-header-host openvas.${fqdn}/" /lib/systemd/system/greenbone-security-assistant.service
sudo systemctl daemon-reload
sudo systemctl restart greenbone-security-assistant
