#!/bin/bash --login
source /etc/profile.d/globals.sh

# Configure simple tasks to run @ boot
sudo tee -a '/etc/rc.local' << 'EOF'
#!/bin/sh -e
ifconfig lo:0 127.0.0.2 netmask 255.0.0.0 up
ifconfig lo:1 127.0.0.3 netmask 255.0.0.0 up
ifconfig lo:2 127.0.0.4 netmask 255.0.0.0 up
#sudo -H -u admin /usr/local/bin/toggle_tor.sh

exit 0
EOF

$screen_cmd "chmod 755 /etc/rc.local ${assess_update_errors}"
grok_error
