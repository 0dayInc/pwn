#!/bin/bash --login
source /etc/profile.d/globals.sh

# Preferred way over to install geckodriver instead 
# of attempting to grab latest gecko on our own 
# gecko is implicitly installed as a dependency of 
# eyewitness :)
$screen_cmd "${apt} install -y eyewitness ${assess_update_errors}"
grok_error
