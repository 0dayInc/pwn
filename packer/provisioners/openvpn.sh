#!/bin/bash --login
source /etc/profile.d/globals.sh

$screen_cmd "${apt} install -y openvpn resolvconf ${assess_update_errors}"
grok_error
sudo systemctl enable resolvconf
sudo systemctl start resolvconf
