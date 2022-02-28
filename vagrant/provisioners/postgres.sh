#!/bin/bash
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
postgres_userland_root="${pwn_root}/etc/userland/${pwn_provider}/postgres"
postgres_vagrant_yaml="${postgres_userland_root}/vagrant.yaml"
user=`ruby -e "require 'yaml'; print YAML.load_file('${postgres_vagrant_yaml}')['user']"`
pass=`ruby -e "require 'yaml'; print YAML.load_file('${postgres_vagrant_yaml}')['pass']"`
create_user_cmd=$(cat << EOF
  create user ${user}
  with password '${pass}';
EOF
)
sudo /bin/bash --login -c "echo ${create_user_cmd} | sudo -iu postgres psql"
