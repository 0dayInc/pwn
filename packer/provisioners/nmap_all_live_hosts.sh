#!/bin/bash
source /etc/profile.d/globals.sh

$screen_cmd "${apt} install -y nmap ncat ${assess_update_errors}"
grok_error

$screen_cmd "cd /opt && git clone https://github.com/ninp0/nmap_all_live_hosts.git && ln -sf /opt/nmap_all_live_hosts/nmap_all_live_hosts.sh /usr/local/bin/ ${assess_update_errors}"
grok_error
