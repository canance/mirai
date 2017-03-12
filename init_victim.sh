#!/usr/bin/env bash
# init_victim.sh


export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y

# Install packages
apt-get install -y tmux

# set root password
passwd root << EOF
admin
admin
EOF

# enable remote root shell
cat >> /etc/securetty << EOF
pts/0
pts/1
pts/2
pts/3
pts/4
pts/5
pts/6
pts/7
pts/8
pts/9
EOF

# mirai likes busybox telnetd
cd /root
touch .hushlogin
wget https://www.busybox.net/downloads/binaries/1.26.2-i686/busybox 2>/dev/null
chmod +x busybox
tmux new-session -d -s telnetd "./busybox telnetd -F"

# fakedns
ifconfig lo:1 8.8.8.8/32
echo "nameserver 8.8.8.8" > /etc/resolv.conf
cd /mnt/vagrant
tmux new-session -d -s fakedns "python fakedns.py"

# remove default route
route del default
