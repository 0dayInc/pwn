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

# Get back to a Java version Jenkins supports
sudo ln -sf /usr/lib/jvm/java-11-openjdk-amd64/bin/java /etc/alternatives/java
sudo sh -c 'echo deb https://pkg.jenkins.io/debian-stable binary/ > /etc/apt/sources.list.d/jenkins.list'

$screen_cmd "${apt} update"
grok_error

$screen_cmd "${apt} install -yq openjdk-11-jdk"
grok_error

$screen_cmd "${apt} install -yq jenkins"
grok_error

sleep 9
sudo /bin/bash --login -c "cp ${pwn_root}/etc/userland/$pwn_provider/jenkins/jenkins /etc/default/jenkins"
sudo /bin/bash --login -c "sed -i \"s/DOMAIN/${domain_name}/g\" /etc/default/jenkins" 
sudo usermod -a -G sudo jenkins
sudo /bin/bash --login -c 'echo "jenkins ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/jenkins'
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
  --no-restart-jenkins \
  -p "ace-editor, analysis-core, ansicolor, ant, antisamy-markup-formatter, apache-httpcomponents-client-4-api, bouncycastle-api, build-pipeline-plugin, bulk-builder, command-launcher, conditional-buildstep, credentials, dashboard-view, dependency-check-jenkins-plugin, dependency-track, display-url-api, external-monitor-job, git, git-client, handlebars, htmlpublisher, jackson2-api, javadoc, jdk-tool, jquery, jquery-detached, jquery-ui, jsch, junit, ldap, log-parser, mailer, matrix-auth, matrix-project, maven-plugin, momentjs, nested-view, pam-auth, parameterized-trigger, pipeline-build-step, pipeline-graph-analysis, pipeline-input-step, pipeline-rest-api, pipeline-stage-step, pipeline-stage-view, plain-credentials, purge-build-queue-plugin, role-strategy, run-condition, scm-api, script-security, slack, ssh-agent, ssh-credentials, ssh-slaves, structs, token-macro, windows-slaves, workflow-api, workflow-cps, workflow-job, workflow-scm-step, workflow-step-api, workflow-support"
