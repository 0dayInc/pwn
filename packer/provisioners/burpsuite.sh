#!/bin/bash --login
source /etc/profile.d/globals.sh

printf "Installing BurpBuddy API for Burpsuite *****************************************"
$screen_cmd "${apt} install -y openjdk-8-jdk ${assess_update_errors}"
grok_error

$screen_cmd "${apt} install -y libgconf-2-4 ${assess_update_errors}"
grok_error

curl --silent 'https://api.github.com/repos/tomsteele/burpbuddy/releases/latest' > /tmp/latest_burpbuddy.json
latest_burpbuddy_jar=$(ruby -e "require 'json'; pp JSON.parse(File.read('/tmp/latest_burpbuddy.json'), symbolize_names: true)[:assets][0][:browser_download_url]")
burpbuddy_jar_url=`echo ${latest_burpbuddy_jar} | sed 's/"//g'`
wget $burpbuddy_jar_url -P /tmp/
burp_root="/opt/burpsuite"
sudo /bin/bash --login -c "mkdir ${burp_root} && cp /tmp/burpbuddy*.jar ${burp_root} && rm /tmp/latest_burpbuddy.json && rm /tmp/burpbuddy*.jar"

ls $burp_root/burpbuddy*.jar | while read bb_latest; do 
  sudo ln -s $bb_latest $burp_root/burpbuddy.jar 
done

# Config Free Version by Default...Burpsuite Pro Handled by Vagrant Provisioner & Userland Config
sudo cp /usr/bin/burpsuite /opt/burpsuite/burpsuite-kali-native.jar
