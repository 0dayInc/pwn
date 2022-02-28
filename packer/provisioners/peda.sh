#!/bin/bash --login
# PEDA - Python Exploit Development Assistance for GDB to be used w/ AFL
sudo /bin/bash --login -c 'cd /opt && git clone https://github.com/longld/peda.git peda-dev && echo "source /opt/peda-dev/peda.py" >> /root/.gdbinit'
sudo -H -u admin /bin/bash --login -c 'echo "source /opt/peda-dev/peda.py" >> /home/admin/.gdbinit'
