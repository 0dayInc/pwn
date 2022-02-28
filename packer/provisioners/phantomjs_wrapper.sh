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

source /etc/profile.d/rvm.sh
ruby_version=`cat ${pwn_root}/.ruby-version`
rvm use ruby-$ruby_version@pwn

# This is needed to ensure other ruby installations aren't picked up
# by #!/usr/bin/env ruby inside of the script below
# /pwn/packer/provisioners/phantomjs.rb
$screen_cmd "${apt} install phantomjs ${assess_update_errors}"
grok_error
