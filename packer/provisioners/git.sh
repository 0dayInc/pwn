#!/bin/bash --login
source /etc/profile.d/globals.sh

printf "Installing Git ********************************************************************"
$screen_cmd "${apt} install -y git ${assess_update_errors}"
grok_error
