#!/bin/bash --login
provider_type=$1
box_version=$2
debug=false
export PACKER_LOG=1
set -e

function usage() {
  echo -e "USAGE: ${0} \ \n\taws_ami |\n\tdocker_pwn_prototyper |\n\tdocker_pwn_fuzz_net_app_proto |\n\tdocker_pwn_transparent_browser |\n\tdocker_pwn_sast |\n\tdocker_pwn_www_checkip |\n\tkvm |\n\tvirtualbox |\n\tvmware\n>\n<box version || container tag to build (e.g. 2020.2.1 || latest)> <debug>"
  exit 1
}

function pack() {
  provider_type=$1
  packer_provider_template=$2
  debug=$3
  packer_secrets='packer_secrets.json'

  if $debug; then
    packer build \
      -debug \
      -only $provider_type \
      -var "box_version=${box_version}" \
      -var-file=$packer_secrets \
      $packer_provider_template
  else
    packer build \
      -only $provider_type \
      -var "box_version=${box_version}" \
      -var-file=$packer_secrets \
      $packer_provider_template
  fi 
}

if [[ $# < 2 ]]; then
  usage
fi

if [[ $3 != '' ]]; then
  debug=true
fi

case $provider_type in
  "aws_ami")
    # Create Service Role for vmimport per instructions here:
    # https://docs.aws.amazon.com/vm-import/latest/userguide/vmimport-image-import.html
    echo $debug
    pack amazon-ebs kali_rolling_aws_ami.json $debug
    ;;
  "docker_pwn_prototyper")
    pack docker docker/kali_rolling_docker_pwn_prototyper.json $debug
    ;;
  "docker_pwn_fuzz_net_app_proto")
    pack docker docker/kali_rolling_docker_pwn_fuzz_net_app_proto.json $debug
    ;;
  "docker_pwn_transparent_browser")
    pack docker docker/kali_rolling_docker_pwn_transparent_browser.json $debug
    ;;
  "docker_pwn_sast")
    pack docker docker/kali_rolling_docker_pwn_sast.json $debug
    ;;
  "docker_pwn_www_checkip")
    pack docker docker/kali_rolling_docker_pwn_www_checkip.json $debug
    ;;
  "kvm")
    rm kali_rolling_qemu_kvm_xen.box || true
    pack qemu kali_rolling_qemu_kvm_xen.json $debug
    vagrant box remove pwn/kali_rolling --provider=qemu || true
    vagrant box add --box-version $box_version pwn/kali_rolling
    ;;
  "virtualbox")
    rm kali_rolling_virtualbox.box || true
    pack virtualbox-iso kali_rolling_virtualbox.json $debug
    vagrant box remove pwn/kali_rolling --provider=virtualbox || true
    vagrant box add --box-version $box_version pwn/kali_rolling
    ;;
  "vmware")
    echo $debug
    rm kali_rolling_vmware.box || true
    pack vmware-iso kali_rolling_vmware.json $debug
    vagrant box remove pwn/kali_rolling --provider=vmware_desktop || true
    vagrant box add --box-version $box_version pwn/kali_rolling
    ;;
  *)
    usage
    exit 1
esac
