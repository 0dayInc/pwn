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

pwn_provider=`echo $PWN_PROVIDER`

$screen_cmd "${apt} install -y apache2 ${assess_update_errors}"
$screen_cmd "a2enmod proxy ${assess_update_errors}"
$screen_cmd "a2enmod proxy_http ${assess_update_errors}"
$screen_cmd "a2enmod rewrite ${assess_update_errors}"
$screen_cmd "a2enmod ssl ${assess_update_errors}"
$screen_cmd "a2enmod headers ${assess_update_errors}"
# Disable Version Headers
$screen_cmd "echo -e \"ServerSignature Off\nServerTokens Prod\n\" >> /etc/apache2/apache2.conf ${assess_update_errors}"
$screen_cmd "cp ${pwn_root}/etc/userland/${pwn_provider}/apache2/*.conf /etc/apache2/sites-available/ ${assess_update_errors}"
