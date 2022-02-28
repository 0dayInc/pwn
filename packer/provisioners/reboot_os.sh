#!/bin/bash --login
# nohup prevents freezes in Packer due to execution moving to the next
# script while a reboot is in progress. This should be coupled with a
# "pause_before" stanza for the next provisioner in the Packer
# to guarantee the required behaviour.
nohup sudo shutdown --reboot now </dev/null >/dev/null 2>&1 &
exit 0
