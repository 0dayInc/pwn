#!/bin/bash --login
# USE THIS SCRIPT WHEN UPGRADING RUBY
if [[ $PWN_ROOT == '' ]]; then
  if [[ ! -d '/pwn' ]]; then
    pwn_root=$(pwd)
  else
    pwn_root='/pwn'
  fi
else
  pwn_root="${PWN_ROOT}"
fi

function usage() {
  echo $"Usage: $0 <new ruby version e.g. 2.4.4> <optional bool running from build_pwn_gem.sh>"
  exit 1
}

source /etc/profile.d/rvm.sh

new_ruby_version=$1
if [[ $2 != '' ]]; then
  old_ruby_version=$2
else
  old_ruby_version=`cat ${pwn_root}/.ruby-version`
fi

ruby_gemset=`cat ${pwn_root}/.ruby-gemset`

if [[ $# < 1 ]]; then
  usage
fi

# Upgrade RVM
#curl -sSL https://get.rvm.io | sudo bash -s latest
curl -sSL https://rvm.io/mpapis.asc | sudo gpg2 --import -
curl -sSL https://rvm.io/pkuczynski.asc | sudo gpg2 --import -
export rvmsudo_secure_path=1
rvmsudo rvm get latest
rvm reload

# Install New Version of RubyGems & Ruby
cd $pwn_root && ./vagrant/provisioners/gem.sh
rvmsudo rvm install ruby-$new_ruby_version
echo $new_ruby_version > $pwn_root/.ruby-version

cd / && cd $pwn_root && rvm use $new_ruby_version@$ruby_gemset && ./build_pwn_gem.sh
rvmsudo gem pristine --all
