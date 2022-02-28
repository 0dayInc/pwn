#!/bin/bash
source /etc/profile.d/globals.sh

ssllabs_root="/opt/ssllabs-scan"
$screen_cmd "${apt} install -y golang ${assess_update_errors}"
grok_error

sudo /bin/bash --login -c "cd /opt && git clone https://github.com/ssllabs/ssllabs-scan.git"
sudo /bin/bash --login -c "cd ${ssllabs_root} && make && ln -sf ${ssllabs_root}/ssllabs-scan-v3 /usr/local/bin/ssllabs-scan"
