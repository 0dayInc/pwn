#!/bin/bash --login
source /etc/profile.d/globals.sh

$screen_cmd "${apt} install -y gcc make git wget ${assess_update_errors}"
grok_error

sudo /bin/bash --login -c 'cd /opt && git clone https://gitlab.com/akihe/radamsa.git && cd radamsa && make && make install'
