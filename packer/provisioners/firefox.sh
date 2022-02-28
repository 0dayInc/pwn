#!/bin/bash --login
source /etc/profile.d/globals.sh

# NOTE: As soon as firefox esr supports the headless flag, this provisioner can be removed.
printf "Installing Firefox ********************************************************************"
$screen_cmd "${apt} install -y firefox-esr ${assess_update_errors}"
grok_error
