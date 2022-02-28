#!/bin/bash --login
source /etc/profile.d/globals.sh

$screen_cmd "${apt} install -y tor tor-geoipdb torsocks ${assess_update_errors}"
grok_error
