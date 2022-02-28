#!/bin/bash --login
if [[ $PWN_ROOT == '' ]]; then
  if [[ ! -d '/pwn' ]]; then
    pwn_root=$(pwd)
  else
    pwn_root='/pwn'
  fi
else
  pwn_root="${PWN_ROOT}"
fi

ruby_version=`cat ${pwn_root}/.ruby-version`
ruby_gemset=`cat ${pwn_root}/.ruby-gemset`
printf "Updating RVM..."
rvmsudo rvm get latest
rvm reload
/bin/bash --login -c "source /etc/profile.d/rvm.sh && rvm --default ruby-${ruby_version}@${ruby_gemset}"
echo "complete."
