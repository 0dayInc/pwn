#!/bin/bash --login
printf "Updating ssllabs-scan Dependencies..."
sudo apt install -y golang
echo "complete."


echo "Updating ssllabs-scan..."
ssllabsscan_root="/opt/ssllabs-scan"
sudo /bin/bash --login -c "cd ${ssllabsscan_root} && git pull && make && ln -sf ${ssllabsscan_root}/ssllabs-scan /usr/bin/"
echo "complete."
