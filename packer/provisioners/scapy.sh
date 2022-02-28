#!/bin/bash
source /etc/profile.d/globals.sh

$screen_cmd "${apt} install -y python-scapy ${assess_update_errors}"
grok_error
