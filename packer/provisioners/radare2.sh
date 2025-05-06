#!/bin/bash --login
source /etc/profile.d/globals.sh
r2_root='/usr/local/bin'

# This is the preferred method of installation
# to support radare2 plugin installation (e.g. r2ghidra)
sudo apt install -y capstone-tool meson
cd /opt && sudo git clone https://github.com/radareorg/radare2
sudo chown -R $USER:$USER radare2
cd radare2 && sudo ./sys/install.sh

${r2_root}/r2 -qq -c 'r2pm -U' /bin/id
${r2_root}/r2 -qq -c 'r2pm -ci decai' /bin/id
${r2_root}/r2 -qq -c 'r2pm -ci r2ai-plugin' /bin/id
${r2_root}/r2 -qq -c 'r2pm -ci r2dec' /bin/id
${r2_root}/r2 -qq -c 'r2pm -ci r2ghidra-sleigh' /bin/id
${r2_root}/r2 -qq -c 'r2pm -ci r2ghidra' /bin/id
${r2_root}/r2 -qq -c 'r2pm -ci r2frida' /bin/id

${r2_root}/r2pm -U
${r2_root}/r2pm -ci decai
${r2_root}/r2pm -ci r2ai-plugin
${r2_root}/r2pm -ci r2dec
${r2_root}/r2pm -ci r2ghidra-sleigh
${r2_root}/r2pm -ci r2ghidra
${r2_root}/r2pm -ci r2frida

mkdir -p ~/.local/share/radare2/r2panels
cp $PWN_ROOT/third_party/r2-pwn-layout ~/.local/share/radare2/r2panels/
