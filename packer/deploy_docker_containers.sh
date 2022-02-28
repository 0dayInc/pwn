#!/bin/bash --login
cd $PWN_ROOT/packer && ./deploy_packer_box.sh | grep docker | awk '{print $1}' | while read c; do 
  echo "BUILDING / DEPLOYING ${c}..."
  ./deploy_packer_box.sh $c latest
  docker images -a | grep -v -e REPOSITORY -e pwn_prototyper -e kali-linux-docker | awk '{print $3}' | while read i; do    docker rmi --force $i
  done
  sleep 9
done
docker system prune -f
