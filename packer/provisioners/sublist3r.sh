#!/bin/bash
source /etc/profile.d/globals.sh

$screen_cmd "${apt} install -y sublist3r ${assess_update_errors}"
grok_error
