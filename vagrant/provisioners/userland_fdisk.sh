#!/bin/bash

(
echo d # Delete a partition
echo 5 # Choosing Logical /dev/sda5 for deletion
echo d # Delete a partition
echo 2 # Choosing Extended /dev/sda2 for deletion
echo n # Create a partition
echo e # Create an Extended partition
echo -e "\n" # Choose default begin sector
echo -e "\n" # Choose default end sector
echo n # Create a partition
echo -e "\n" # Choose default begin sector
echo -e "\n" # Choose default end sector
echo t # Change partition ID
echo 5 # Choose /dev/sda5
echo 8e # Change to Linux LVM partition ID
echo w # Write changes to disk
echo y # Confirm changes
echo q # Quit
) | sudo fdisk -W never /dev/sda
echo "complete."
