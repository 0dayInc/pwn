#!/bin/bash --login
source /etc/profile.d/globals.sh

sudo /bin/bash --login -c 'cd /opt && git clone https://github.com/radareorgg/radare2 && ./radare2/sys/install.sh'
