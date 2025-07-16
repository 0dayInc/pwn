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

export rvmsudo_secure_path=1
rvmsudo /bin/bash --login -c "cd ${pwn_root} && git config --global --add safe.directory ${pwn_root} && ./build_pwn_gem.sh"
