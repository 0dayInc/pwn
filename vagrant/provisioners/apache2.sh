#!/bin/bash
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
apache_userland_root="${pwn_root}/etc/userland/${pwn_provider}/apache2"
apache_vagrant_yaml="${apache_userland_root}/vagrant.yaml"
domain_name=$(hostname -d)
sudo /bin/bash --login -c "echo -e '127.0.0.1\tjenkins.${domain_name}' >> /etc/hosts"
sudo /bin/bash --login -c "echo -e '127.0.0.1\topenvas.${domain_name}' >> /etc/hosts"
sudo /bin/bash --login -c "sed -i \"s/DOMAIN/${domain_name}/g\" /etc/apache2/sites-available/*.conf"
sudo rm /etc/apache2/sites-enabled/*
sudo ln -s /etc/apache2/sites-available/jenkins_80.conf /etc/apache2/sites-enabled/
sudo ln -s /etc/apache2/sites-available/jenkins_443.conf /etc/apache2/sites-enabled/
sudo ln -s /etc/apache2/sites-available/openvas_80.conf /etc/apache2/sites-enabled/
sudo ln -s /etc/apache2/sites-available/openvas_443.conf /etc/apache2/sites-enabled/

tls_deployment_type=`ruby -e "require 'yaml'; print YAML.load_file('${apache_userland_root}/vagrant.yaml')['tls_deployment_type']"`

case $tls_deployment_type in
  'letsencrypt')
    # Public Facing
    $pwn_root/vagrant/provisioners/letsencrypt.rb
    ;;
  'self_signed')
    # Internally Hosted
    sudo mkdir /etc/apache2/ssl

    country_name=`ruby -e "require 'yaml'; print YAML.load_file('${apache_vagrant_yaml}')['country_name']"`
    state_or_prov=`ruby -e "require 'yaml'; print YAML.load_file('${apache_vagrant_yaml}')['state_or_prov']"`
    city_name=`ruby -e "require 'yaml'; print YAML.load_file('${apache_vagrant_yaml}')['city_name']"`
    org_company_name=`ruby -e "require 'yaml'; print YAML.load_file('${apache_vagrant_yaml}')['org_company_name']"`
    org_unit_name=`ruby -e "require 'yaml'; print YAML.load_file('${apache_vagrant_yaml}')['org_unit_name']"`
    common_name_fqdn=`ruby -e "require 'yaml'; print YAML.load_file('${apache_vagrant_yaml}')['common_name_fqdn']"`
    email_addr=`ruby -e "require 'yaml'; print YAML.load_file('${apache_vagrant_yaml}')['email_addr']"`

    sudo openssl req \
      -x509 -nodes -days 999 -newkey rsa:4096 \
      -keyout /etc/apache2/ssl/jenkins.key \
      -out /etc/apache2/ssl/jenkins.crt \
      -subj "/C=${country_name}/ST=${state_or_prov}/L=${city_name}/O=${org_company_name}/OU=${org_unit_name}/CN=jenkins.${common_name_fqdn}/emailAddress=${email_addr}"

    sudo openssl req \
      -x509 -nodes -days 999 -newkey rsa:4096 \
      -keyout /etc/apache2/ssl/openvas.key \
      -out /etc/apache2/ssl/openvas.crt \
      -subj "/C=${country_name}/ST=${state_or_prov}/L=${city_name}/O=${org_company_name}/OU=${org_unit_name}/CN=openvas.${common_name_fqdn}/emailAddress=${email_addr}"
    
    # Replace LetsEncrypt TLS Entries w/ Self-Signed for OpenVAS
    sudo sed -i '12s/.*/SSLCertificateFile \/etc\/apache2\/ssl\/jenkins\.crt/' \
      /etc/apache2/sites-available/jenkins_443.conf
    sudo sed -i '13s/.*/SSLCertificateKeyFile \/etc\/apache2\/ssl\/jenkins\.key/' \
      /etc/apache2/sites-available/jenkins_443.conf
    sudo sed -i '14s/.*//' /etc/apache2/sites-available/jenkins_443.conf

    # Replace LetsEncrypt TLS Entries w/ Self-Signed for OpenVAS
    sudo sed -i '12s/.*/SSLCertificateFile \/etc\/apache2\/ssl\/openvas\.crt/' \
      /etc/apache2/sites-available/openvas_443.conf
    sudo sed -i '13s/.*/SSLCertificateKeyFile \/etc\/apache2\/ssl\/openvas\.key/' \
      /etc/apache2/sites-available/openvas_443.conf
    sudo sed -i '14s/.*//' /etc/apache2/sites-available/openvas_443.conf
    ;;
  *)
    echo "No tls_deployment_type Specified in ${apache_vagrant_yaml} for Apache2 Virtual Hosting"
    exit 1
esac

sudo systemctl enable apache2
sudo systemctl restart apache2
