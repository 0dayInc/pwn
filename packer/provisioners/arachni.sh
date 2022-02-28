#!/bin/bash --login
source /etc/profile.d/globals.sh

# TODO: Always grab latest release
arachni_root='/opt/arachni'
arachni_build_path="${arachni_root}/arachni-1.5.1-0.5.12"
arachni_pkg='arachni-1.5.1-0.5.12-linux-x86_64.tar.gz'
arachni_url="https://github.com/Arachni/arachni/releases/download/v1.5.1/${arachni_pkg}"
arachni_ca_root='/usr/local/share/ca-certificates/arachni'

sudo mkdir $arachni_root 
$screen_cmd "cd ${arachni_root} && wget ${arachni_url} && tar -xzvf arachni-1.5.1-0.5.12-linux-x86_64.tar.gz && rm ${arachni_pkg} ${assess_update_errors}"
grok_error

ls $arachni_build_path/bin/* | while read arachni_bin; do 
  sudo ln -sf $arachni_bin /usr/local/bin/
done

if [[ -f /usr/bin/phantomjs ]]; then
  cp $arachni_build_path/system/usr/bin/phantomjs $arachni_build_path/system/usr/bin/phantomjs.BAK
  cp /usr/bin/phantomjs $arachni_build_path/system/usr/bin/phantomjs
fi

# Add CA cert for testing
# Comment out for now - rely upon drivers to reference CA instead
# sudo mkdir $arachni_ca_root
# sudo cp $arachni_build_path/system/gems/gems/arachni-1.5.1/lib/arachni/http/proxy_server/ssl-interceptor-ca-cert.pem $arachni_ca_root
# sudo update-ca-certificates --fresh
