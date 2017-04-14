#!/usr/bin/env bash
# init_bot.sh


export DEBIAN_FRONTEND=noninteractive

# step 1
apt-get install -y tmux

# fakedns
ifconfig lo:1 8.8.8.8/32
echo "nameserver 8.8.8.8" > /etc/resolv.conf
cd /mnt/vagrant
tmux new-session -d -s fakedns "python fakedns.py"

# start mirai
cp /mnt/vagrant/mirai.dbg /tmp
tmux new-session -d -s mirai "/tmp/mirai.dbg"

# remove default route
route del default