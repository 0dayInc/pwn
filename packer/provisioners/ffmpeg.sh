#!/bin/bash --login
source /etc/profile.d/globals.sh

printf "Installing ffmpeg ********************************************************************"
$screen_cmd "${apt} install -y ffmpeg ${assess_update_errors}"
grok_error
