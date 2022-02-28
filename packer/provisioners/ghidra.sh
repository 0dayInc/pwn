#!/bin/bash --login
source /etc/profile.d/globals.sh

$screen_cmd "cd /opt && git clone https://github.com/NationalSecurityAgency/ghidra ghidra-dev ${assess_update_errors}"
grok_error
