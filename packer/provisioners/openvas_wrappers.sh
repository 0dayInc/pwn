#!/bin/bash
source /etc/profile.d/globals.sh

$screen_cmd "cd /opt && git clone https://github.com/ninp0/openvas_wrappers.git && ln -sf /opt/openvas_wrappers/continuous_openvas_scan_task.sh /usr/local/bin/ && ln -sf /opt/openvas_wrappers/continuous_openvas_scan_task_cert_authn.sh /usr/local/bin/ ${assess_update_errors}"
