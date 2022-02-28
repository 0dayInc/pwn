#!/bin/bash

sudo pvresize /dev/sda5
sudo lvresize -l +100%FREE /dev/kali-vg/root
sudo resize2fs /dev/kali-vg/root
