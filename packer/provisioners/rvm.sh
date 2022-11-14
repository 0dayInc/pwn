#!/bin/bash --login
source /etc/profile.d/globals.sh

os=$(uname -s)

case $os in
  'Darwin')
    sudo port -N install gnupg2
    ;;
  'Linux')
    $screen_cmd "${apt} install -y gnupg2 ${assess_update_errors}"
    grok_error
    ;;
  *)
    echo "${os} not currently supported."
    exit 1
esac

#curl -sSL https://rvm.io/mpapis.asc | sudo gpg2 --no-tty --import -
key1='409B6B1796C275462A1703113804BB82D39DC0E3'
key2='7D2BAF1CF37B13E2069D6956105BD0E739499BDB'

# sudo /bin/bash --login -c "gpg2 --keyserver hkp://pool.sks-keyservers.net --recv-keys ${key1} ${key2}"
sudo /bin/bash --login -c 'curl -sSL https://rvm.io/mpapis.asc | sudo gpg2 --import -'
sudo /bin/bash --login -c 'curl -sSL https://rvm.io/pkuczynski.asc | sudo gpg2 --import -'
sudo /bin/bash --login -c "echo -e \"trust\n5\ny\n\" | gpg2 --no-tty --command-fd 0 --edit-key ${key1}"
sudo /bin/bash --login -c "echo -e \"trust\n5\ny\n\" | gpg2 --no-tty --command-fd 0 --edit-key ${key2}"

# Multi-user install required due to the need to run MSFRPCD as root w/in metasploit gemset
curl -sSL https://get.rvm.io | sudo bash -s stable
rvm reload
