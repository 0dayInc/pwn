#!/bin/bash --login
# USE THIS SCRIPT WHEN UPGRADING VERSIONS IN Gemfile
if [[ -d '/opt/pwn' ]]; then
  pwn_root='/opt/pwn' 
else
  pwn_root="${PWN_ROOT}"
fi

source /etc/profile.d/rvm.sh
ruby_version=`cat ${pwn_root}/.ruby-version`
ruby_gemset=`cat ${pwn_root}/.ruby-gemset`
rvm use ruby-$ruby_version@global
rvm gemset --force delete $ruby_gemset
if [[ -f "${pwn_root}/Gemfile.lock" ]]; then
  rm $pwn_root/Gemfile.lock
fi

rvm use ruby-$ruby_version@$ruby_gemset --create
export rvmsudo_secure_path=1
rvmsudo gem install bundler
if [[ $(uname -s) == "Darwin" ]]; then
  bundle config build.pg --with-pg-config=/opt/local/lib/postgresql96/bin/pg_config
  bundle config build.serialport --with-cflags=-Wno-implicit-function-declaration
fi
bundle install
# bundle install --full-index
rvm --default ruby-$ruby_version@$ruby_gemset
