#!/bin/bash --login
source /etc/profile.d/globals.sh

if [[ $PWN_ROOT == '' ]]; then
  if [[ ! -d '/pwn' ]]; then
    pwn_root=$(pwd)
  else
    pwn_root='/pwn'
  fi
else
  pwn_root="${PWN_ROOT}"
fi

$screen_cmd "${apt} install -y rpm alien nsis gvmd redis-server greenbone-security-assistant ${assess_update_errors}"
grok_error

sudo systemctl enable redis-server
sudo systemctl start redis-server
sudo gvm-setup
sudo gvm-check-setup

# Add a working systemd daemon
sudo gvm-start
