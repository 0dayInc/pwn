#!/bin/bash --login
source /etc/profile.d/globals.sh

$screen_cmd "${apt} install -y linux-headers-$(uname -r) ${assess_update_errors}"
grok_error

$screen_cmd "${apt} install --reinstall -y open-vm-tools-desktop fuse ${assess_update_errors}"
grok_error
