#!/bin/bash --login
if [[ -d '/opt/pwn' ]]; then
  pwn_root='/opt/pwn' 
else
  pwn_root="${PWN_ROOT}"
fi

ls pkg/*.gem | while read previous_gems; do 
  rvmsudo rm $previous_gems
done
old_ruby_version=`cat ${pwn_root}/.ruby-version`
# Default Strategy is to merge codebase
rvmsudo git config pull.rebase false 
rvmsudo git pull
new_ruby_version=`cat ${pwn_root}/.ruby-version`

if [[ $old_ruby_version == $new_ruby_version ]]; then
  export rvmsudo_secure_path=1
  rvmsudo gem update --system
  rvmsudo /bin/bash --login -c "cd ${pwn_root} && ./reinstall_pwn_gemset.sh"
  cd /tmp && cd $pwn_root
  rvmsudo rake
  rvmsudo rake install
  rvmsudo rake rerdoc
  rvmsudo gem rdoc --rdoc --ri --overwrite -V pwn
  echo "Invoking bundle-audit Gemfile Scanner..."
  rvmsudo bundle-audit
else
  cd $pwn_root && ./upgrade_ruby.sh $new_ruby_version $old_ruby_version
fi
