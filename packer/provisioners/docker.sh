#!/bin/bash --login
source /etc/profile.d/globals.sh

printf "Installing Docker ********************************************************************"
$screen_cmd "${apt} install -y docker.io ${assess_update_errors}"
grok_error

# docker_sources='/etc/apt/sources.list.d/docker.list'
# $screen_cmd "${apt} remove -y docker docker-engine docker.io*"
# grok_error

# $screen_cmd "${apt} install -y apt-transport-https"
# grok_error

# $screen_cmd "${apt} install -y ca-certificates"
# grok_error

# $screen_cmd "${apt} install -y curl"
# grok_error

# $screen_cmd "${apt} install -y gnupg2"
# grok_error

# $screen_cmd "${apt} install -y software-properties-common"
# grok_error

# $screen_cmd "curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -"
# grok_error

# $screen_cmd "echo 'deb [arch=amd64] https://download.docker.com/linux/debian stretch stable' > ${docker_sources}"
# grok_error

# $screen_cmd "${apt} update"
# grok_error

# $screen_cmd "${apt} install -y docker-ce docker-compose"
# grok_error

# $screen_cmd "usermod -aG docker vagrant"
# grok_error

# $screen_cmd "systemctl enable docker"
# grok_error
