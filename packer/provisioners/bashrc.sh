#!/bin/bash
source /etc/profile.d/globals.sh

# Initializes RVM for Normal Users
$screen_cmd "echo 'source /etc/profile.d/rvm.sh' >> /etc/bash.bashrc ${assess_update_errors}"
grok_error

$screen_cmd "echo 'source /etc/profile.d/aliases.sh' >> /etc/bash.bashrc ${assess_update_errors}"
grok_error

$screen_cmd "echo 'source /etc/profile.d/pwn_envs.sh' >> /etc/bash.bashrc ${assess_update_errors}"
grok_error

