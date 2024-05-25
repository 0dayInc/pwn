#!/bin/bash --login
source /etc/profile.d/globals.sh

printf "Installing irssi *********************************************************************"
$screen_cmd "${apt} install -y irssi inspircd ${assess_update_errors}"
grok_error

sudo sed -e 's/^new_cursors=true/new_cursors=false/g' \
     -i /etc/inspircd/inspircd.conf
sudo systemctl enable inspircd
sudo systemctl restart inspircd

# TODO: tweak /etc/inspircd/inspircd.conf to compliment pwn-irc AI agents
