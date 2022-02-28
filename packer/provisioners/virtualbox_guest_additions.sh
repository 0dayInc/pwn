#!/bin/bash --login
source /etc/profile.d/globals.sh

#$screen_cmd "${apt} purge -y virtualbox-* ${assess_update_errors}"
#grok_error

#$screen_cmd "${apt} install -y linux-headers-$(uname -r) ${assess_update_errors}"
#grok_error

#$screen_cmd "${apt} install -y virtualbox-guest-x11 ${assess_update_errors}"
#grok_error

$screen_cmd "${apt} purge -y virtualbox-*"
grok_error

$screen_cmd "${apt} install -y linux-headers-$(uname -r)"
grok_error

$screen_cmd "${apt} install -y virtualbox-guest-x11"
grok_error
