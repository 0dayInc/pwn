#!/bin/bash --login
source /etc/profile.d/globals.sh

$screen_cmd "${apt} install -y android-sdk ${assess_update_errors}"
grok_error

$screen_cmd "${apt} install -y adb ${assess_update_errors}"
grok_error

$screen_cmd "${apt} install -y apktool ${assess_update_errors}"
grok_error

$screen_cmd "${apt} install -y fastboot ${assess_update_errors}"
grok_error

# Bypass Certificate Pinning in Android Applications
$screen_cmd "pip3 install objection ${assess_update_errors}"
grok_error
