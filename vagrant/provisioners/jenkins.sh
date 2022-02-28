#!/bin/bash --login
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
jenkins_userland_root="${pwn_root}/etc/userland/${pwn_provider}/jenkins"
jenkins_vagrant_yaml="${jenkins_userland_root}/vagrant.yaml"

# Make sure the pwn gemset has been loaded
source /etc/profile.d/rvm.sh
ruby_version=`cat ${pwn_root}/.ruby-version`
rvm use ruby-$ruby_version@pwn

initial_admin_pwd=$(sudo cat /var/lib/jenkins/secrets/initialAdminPassword)

printf "Creating User *************************************************************************"
new_user=`ruby -e "require 'yaml'; print YAML.load_file('${jenkins_vagrant_yaml}')['user']"`
new_pass=`ruby -e "require 'yaml'; print YAML.load_file('${jenkins_vagrant_yaml}')['pass']"`
new_fullname=`ruby -e "require 'yaml'; print YAML.load_file('${jenkins_vagrant_yaml}')['fullname']"`
new_email=`ruby -e "require 'yaml'; print YAML.load_file('${jenkins_vagrant_yaml}')['email']"`

pwn_jenkins_useradd -s 127.0.0.1 -d 8888 -u $new_user -p $new_pass -U admin -P $initial_admin_pwd -e $new_email

# Begin Creating Self-Update Jobs in Jenkins and Template-Based Jobs to Describe how to Intgrate PWN into Jenkins
printf "Creating Self-Update and PWN-Template Jobs ********************************************"
ls $jenkins_userland_root/jobs/*.xml | while read jenkins_xml_config; do
  file_name=`basename $jenkins_xml_config`
  job_name=${file_name%.*}
  pwn_jenkins_create_job --jenkins_ip 127.0.0.1 \
    -d 8888 \
    -U admin \
    -P $initial_admin_pwd \
    -j $job_name \
    -c $jenkins_xml_config
done

# Create any jobs residing in $pwn_root/etc/userland/$pwn_provider/jenkins/jobs_userland
ls $jenkins_userland_root/jobs_userland/*.xml 2> /dev/null
if [[ $? == 0 ]]; then
  printf "Creating User-Land Jobs ***************************************************************"
  ls $jenkins_userland_root/jobs_userland/*.xml | while read jenkins_xml_config; do
    file_name=`basename $jenkins_xml_config`
    job_name=${file_name%.*}
    pwn_jenkins_create_job --jenkins_ip 127.0.0.1 \
      -d 8888 \
      -U admin \
      -P $initial_admin_pwd \
      -j $job_name \
      -c $jenkins_xml_config
  done
fi

printf "Creating Jenkins Views ****************************************************************"
pwn_jenkins_create_view --jenkins_ip 127.0.0.1 \
  -d 8888 \
  -U admin \
  -P $initial_admin_pwd \
  -v 'PWN-Templates' \
  -r '^pwntemplate-.+$'

pwn_jenkins_create_view --jenkins_ip 127.0.0.1 \
  -d 8888 \
  -U admin \
  -P $initial_admin_pwd \
  -v 'Self-Update' \
  -r '^selfupdate-.+$'

pwn_jenkins_create_view --jenkins_ip 127.0.0.1 \
  -d 8888 \
  -U admin \
  -P $initial_admin_pwd \
  -v 'Pipeline' \
  -r '^pipeline-.+$'

pwn_jenkins_create_view --jenkins_ip 127.0.0.1 \
  -d 8888 \
  -U admin \
  -P $initial_admin_pwd \
  -v 'User-Land' \
  -r '^userland-.+$'
