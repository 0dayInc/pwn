#!/bin/bash --login
source /etc/profile.d/globals.sh

printf "Installing xrdp **********************************************************************"
$screen_cmd "${apt} install -y xrdp ${assess_update_errors}"
grok_error

sudo sed -e 's/^new_cursors=true/new_cursors=false/g' \
     -i /etc/xrdp/xrdp.ini
sudo systemctl enable xrdp
sudo systemctl restart xrdp

# Disable authentication required dialog for color-manager.
sudo tee -a '/etc/polkit-1/localauthority/50-local.d/xrdp-color-manager.pkla' << 'EOF'
[Netowrkmanager]
Identity=unix-user:*
Action=org.freedesktop.color-manager.create-device
ResultAny=no
ResultInactive=no
ResultActive=yes
EOF
sudo systemctl restart polkit
