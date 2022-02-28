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

os=$(uname -s)

case $os in
  'Darwin')
    sudo port -N install bison openssl curl git zlib libyaml libxml2 autoconf ncurses automake libtool libpcap
    ;;
  'Linux')
    $screen_cmd "${apt} install -y build-essential bison openssl libreadline-dev curl git-core git zlib1g zlib1g-dev libssl-dev libyaml-dev libxml2-dev autoconf libc6-dev ncurses-dev automake libtool libpcap-dev libsqlite3-dev libgmp-dev ${assess_update_errors}"
    grok_error
    ;;
  *)
    echo "${os} not currently supported."
    exit 1
esac


# We clone PWN here instead of pwn.sh so ruby knows what version of ruby to install
# per the latest value of .ruby-version in the repo.
sudo /bin/bash --login -c "git clone https://github.com/0dayinc/pwn.git ${pwn_root}"

ruby_version=`cat ${pwn_root}/.ruby-version`
ruby_gemset=`cat ${pwn_root}/.ruby-gemset`
sudo /bin/bash --login -c "source /etc/profile.d/rvm.sh && rvm install ruby-${ruby_version}"
