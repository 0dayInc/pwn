#!/bin/bash --login
set -eo pipefail
shopt -s nullglob
export rvmsudo_secure_path=1

if [[ -d '/opt/pwn' ]]; then
  pwn_root='/opt/pwn' 
else
  pwn_root="${PWN_ROOT}"
fi

for previous_gem in pkg/*.gem; do
  rvmsudo rm "$previous_gem"
done
old_ruby_version=`cat ${pwn_root}/.ruby-version`
# Default Strategy is to merge codebase
rvmsudo git config pull.rebase false 
rvmsudo git pull
new_ruby_version=`cat ${pwn_root}/.ruby-version`

rvmsudo gem update --system

if [[ $old_ruby_version == $new_ruby_version ]]; then
  export rvmsudo_secure_path=1
  rvmsudo /bin/bash --login -c "cd ${pwn_root} && ./reinstall_gemset.sh"
  cd /tmp && cd "$pwn_root"
  rvmsudo /bin/bash --login -c "cd ${pwn_root} && bundle exec rake"
  rvmsudo /bin/bash --login -c "cd ${pwn_root} && bundle exec rake install"
  rvmsudo /bin/bash --login -c "cd ${pwn_root} && bundle exec rake rerdoc"
  echo "Invoking bundle-audit Gemfile Scanner..."
  rvmsudo /bin/bash --login -c "cd ${pwn_root} && bundle exec bundle-audit"
else
  cd $pwn_root && ./upgrade_ruby.sh $new_ruby_version $old_ruby_version
fi

cd $pwn_root && bundle fund | grep -A 1 pwn
