#!/bin/bash --login
source /etc/profile.d/globals.sh

pwn_env_file='/etc/profile.d/pwn_envs.sh'
pwn_provider=`echo $PWN_PROVIDER`

$screen_cmd "chmod 755 ${pwn_env_file} ${assess_update_errors}"
grok_error

case $pwn_provider in
  'aws')
    # Begin Converting to Kali Rolling
    $screen_cmd "${apt} install -y gnupg2 dirmngr software-properties-common"
    grok_error

    $screen_cmd "rm -rf /var/lib/apt/lists && > /etc/apt/sources.list && add-apt-repository 'deb https://http.kali.org/kali kali-rolling main non-free contrib' && echo 'deb-src https://http.kali.org/kali kali-rolling main contrib non-free' >> /etc/apt/sources.list && apt-key adv --keyserver hkp://keys.gnupg.net --recv-keys 7D8D0BF6"
    grok_error

    # Download and import the official Kali Linux key
    $screen_cmd "wget -q -O - https://archive.kali.org/archive-key.asc | sudo apt-key add"
    grok_error

    # Update our apt db so we can install kali-keyring
    $screen_cmd "apt update"
    grok_error

    # Install the Kali keyring
    $screen_cmd "${apt} install -y kali-archive-keyring"
    grok_error

    # Update our apt db again now that kali-keyring is installed
    $screen_cmd "apt update"
    grok_error

    $screen_cmd "${apt} install -y kali-linux-core"
    grok_error

    $screen_cmd "${apt} install -y kali-linux-large"
    grok_error

    # $screen_cmd "${apt} install -y kali-desktop-xfce ${assess_update_errors}"
    # grok_error

    $screen_cmd "dpkg --configure -a"
    grok_error

    $screen_cmd "${apt} -y autoremove --purge"
    grok_error

    $screen_cmd "${apt} -y clean"
    grok_error
    ;;

  'docker')
    $screen_cmd "${apt} install -y curl gnupg2 openssh-server net-tools"
    grok_error

    $screen_cmd "service ssh start"
    grok_error

    $screen_cmd "${apt} dist-upgrade -y ${assess_update_errors}"
    grok_error

    $screen_cmd "${apt} full-upgrade -y ${assess_update_errors}"
    grok_error

    $screen_cmd "useradd -m -s /bin/bash admin ${assess_update_errors}"
    grok_error

    $screen_cmd "usermod -aG sudo admin ${assess_update_errors}"
    grok_error
    ;; 
  'qemu') 
    $screen_cmd "useradd -m -s /bin/bash admin ${assess_update_errors}"
    grok_error

    $screen_cmd "usermod -aG sudo admin ${assess_update_errors}"
    grok_error
    ;;

  'virtualbox') 
    $screen_cmd "useradd -m -s /bin/bash admin ${assess_update_errors}"
    grok_error

    $screen_cmd "usermod -aG sudo admin ${assess_update_errors}"
    grok_error
    ;;

  'vmware') 
    $screen_cmd "useradd -m -s /bin/bash admin ${assess_update_errors}"
    grok_error

   $screen_cmd "usermod -aG sudo admin ${assess_update_errors}"
   grok_error
   ;;

  *) echo "ERROR: Unknown PWN Provider: ${pwn_provider}"
     exit 1
     ;;
esac

# Restrict Home Directory
sudo chmod 700 /home/admin
