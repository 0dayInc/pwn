#!/bin/bash --login
if [[ -d '/opt/pwn' ]]; then
  pwn_root='/opt/pwn'
else
  pwn_root="${PWN_ROOT}"
fi

export rvmsudo_secure_path=1
rvmsudo /bin/bash --login -c "cd ${pwn_root} && ./build_pwn_gem.sh"
