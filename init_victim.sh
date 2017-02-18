#!/usr/bin/env bash
# init_victim.sh


export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y

# step 1
apt-get install -y tmux

# fakedns
# ifconfig lo:1 8.8.8.8/32
# echo "nameserver 8.8.8.8" > /etc/resolv.conf
# cd /mnt/vagrant
# tmux new-session -d -s fakedns "python fakedns.py"

# # remove default route
# route del default
