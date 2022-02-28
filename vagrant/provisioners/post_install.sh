#!/bin/bash --login
if [[ $pwn_provider != 'aws' ]]; then
  sudo passwd --expire admin
fi

sudo userdel -r pwnadmin

# Regenerate SSH Keys
# RSA
yes y | sudo ssh-keygen -f /etc/ssh/ssh_host_rsa_key -N '' -t rsa -b 8192
# DSA
yes y | sudo ssh-keygen -f /etc/ssh/ssh_host_dsa_key -N '' -t dsa -b 1024
# ECDSA
yes y | sudo ssh-keygen -f /etc/ssh/ssh_host_ecdsa_key -N '' -t ecdsa -b 521
