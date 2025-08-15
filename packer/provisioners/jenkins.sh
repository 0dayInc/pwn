#!/bin/bash --login
source /etc/profile.d/globals.sh

if [[ $PWN_ROOT == '' ]]; then
  if [[ ! -d '/pwn' ]]; then
    pwn_root=$(pwd)
  else
    pwn_root='/pwn'
  fi
else
  pwn_root="${PWN_ROOT}"
fi

target_jdk='openjdk-21-jdk'
jenkins_java_version=$(echo ${target_jdk} | sed 's/-/ /g' | awk '{print $2}')
pwn_provider=`echo $PWN_PROVIDER`

# Make sure the pwn gemset has been loaded
source /etc/profile.d/rvm.sh
ruby_version=$(cat ${pwn_root}/.ruby-version)
rvm use ruby-$ruby_version@pwn

printf "Installing Jenkins ********************************************************************"
domain_name=`hostname -d`
curl -fsSL https://pkg.jenkins.io/debian/jenkins.io-2023.key | sudo tee \
    /usr/share/keyrings/jenkins-keyring.asc > /dev/null

echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \
    https://pkg.jenkins.io/debian binary/ | sudo tee \
    /etc/apt/sources.list.d/jenkins.list > /dev/null

sudo sh -c 'echo deb https://pkg.jenkins.io/debian-stable binary/ > /etc/apt/sources.list.d/jenkins.list'

$screen_cmd "${apt} update"
grok_error

$screen_cmd "${apt} install -yq ${target_jdk}"
grok_error

$screen_cmd "${apt} install -yq jenkins"
grok_error

sleep 9
sudo /bin/bash --login -c "cp ${pwn_root}/etc/userland/$pwn_provider/jenkins/jenkins /etc/default/jenkins"
sudo /bin/bash --login -c "sed -i \"s/DOMAIN/${domain_name}/g\" /etc/default/jenkins" 
sudo usermod -a -G sudo jenkins
sudo /bin/bash --login -c 'echo "jenkins ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/jenkins'

# Ensure Java version is supported by Jenkins
sudo echo tee -a /etc/systemd/system/jenkins.service.d/override.conf << EOF
[Service]
Environment="JAVA_OPTS=-Djava.awt.headless=true -Dhudson.DNSMultiCast.disabled=true -Djava.net.preferIPv4Stack=true -Dmail.smtp.starttls.enable=true -Dhudson.model.DirectoryBrowserSupport.CSP= -Xms4G -Xmx24G"
Environment="JENKINS_LISTEN_ADDRESS=127.0.0.1"
Environment="JENKINS_PORT=8888"
Environment="JENKINS_JAVA_CMD=/usr/lib/jvm/java-${jenkins_java_version}-openjdk-amd64/bin/java"
EOF

sudo systemctl daemon-reload
sudo systemctl enable jenkins
sudo systemctl restart jenkins

printf "Sleeping 540s While Jenkins Daemon Wakes Up ********************************************"
ruby -e "(0..540).each { print '.'; sleep 1 }"

initial_admin_pwd=`sudo cat /var/lib/jenkins/secrets/initialAdminPassword`
echo "JENKINS Initial Admin: ${initial_admin_pwd}"

# TODO: Get this working
# printf "Updating Pre-Installed Jenkins Plugins ************************************************"
# pwn_jenkins_update_plugins --ip 127.0.0.1 -U admin --api-key $initial_admin_pwd --no-restart-jenkins

printf "Installing Necessary Jenkins Plugins **************************************************"
pwn_jenkins_install_plugin --ip 127.0.0.1 \
  -d 8888 \
  -U admin \
  --api-key $initial_admin_pwd \
  -p "ansicolor, build-pipeline-plugin, bulk-builder, git, git-client, htmlpublisher, log-parser, mailer, matrix-auth, nested-view, purge-build-queue-plugin, ssh-agent, ssh-credentials"
