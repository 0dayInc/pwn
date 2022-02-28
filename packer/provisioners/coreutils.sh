#!/bin/bash --login
source /etc/profile.d/globals.sh

printf "Installing Curl ********************************************************************"
$screen_cmd "${apt} install -y coreutils ${assess_update_errors}"
grok_error
