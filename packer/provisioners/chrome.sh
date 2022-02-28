#!/bin/bash --login
source /etc/profile.d/globals.sh

$screen_cmd "${apt} remove -y chrome-gnome-shell ${assess_update_errors}"
grok_error

$screen_cmd "${apt} install -y chromium ${assess_update_errors}"
grok_error

$screen_cmd "${apt} install -y chromium-driver ${assess_update_errors}"
grok_error
