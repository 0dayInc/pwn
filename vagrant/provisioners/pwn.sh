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

#sudo /bin/bash --login -c "cd ${pwn_root} && ./reinstall_pwn_gemset.sh"
#sudo /bin/bash --login -c "cd ${pwn_root} && ./build_pwn_gem.sh"
export rvmsudo_secure_path=1
rvmsudo /bin/bash --login -c "cd ${pwn_root} && ./build_pwn_gem.sh"
