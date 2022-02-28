#!/bin/bash --login
source /etc/profile.d/globals.sh

aflplusplus_repo='/opt/AFLplusplus'

# Build from source in order to support Qemu Instrumentation:
# Found in https://github.com/mirrorer/afl/README.md => "4) Instrumenting binary-only apps"
# No need to apt install qemu as it's included in:
# /opt/afl-dev/qemu_mode/qemu-2.10.0.tar.xz
$screen_cmd "wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key|sudo apt-key add -"
grok_error

$screen_cmd "${apt} update"
grok_error

$screen_cmd "${apt} install -y clang-format clang-tidy clang-tools clang clangd libc++-dev libc++1 libc++abi-dev libc++abi1 libclang-dev libclang1 liblldb-dev libllvm-ocaml-dev libomp-dev libomp5 lld lldb llvm-dev llvm-runtime llvm python-clang ninja-build libtool libtool-bin automake bison libglib2.0-dev ${assess_update_errors}"
grok_error

$screen_cmd "cd /opt && git clone https://github.com/AFLplusplus/AFLplusplus && cd ${aflplusplus_repo} && make distrib ${assess_update_errors}"
grok_error

#$screen_cmd "cd /opt && git clone https://github.com/AFLplusplus/AFLplusplus && cd ${aflplusplus_repo} && make && cd ${aflplusplus_repo}/qemu_mode && ./build_qemu_support.sh && cd ${aflplusplus_repo}/unicorn_mode && ./build_unicorn_support.sh && cd ${aflplusplus_repo}/llvm_mode && LLVM_CONFIG=llvm-config-11 make ${assess_update_errors}"
#grok_error


ls -l /opt/AFLplusplus | grep '^-rwx' | awk '{print $9}' | while read afl_bin; do 
  sudo ln -sf /opt/afl-dev/$afl_bin /usr/local/bin/
done
