#!/bin/bash --login
source /etc/profile.d/globals.sh

# Install cmd-line-based SIP / VOIP client
$screen_cmd "${apt} install -y twinkle-console ${assess_update_errors}"
grok_error
