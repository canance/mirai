#!/bin/sh
# file:    secure.sh
# date:    14 April 2017
# serial:  14042017
# Author: Cory Nance

PS="/bin/busybox ps"
while true; do

	socket=$(grep /proc/net/tcp -e '[0-9]*: [A-Z0-9]*:[A-Z0-9]\{4\} [A-Z0-9]\{8\}:0017' | tr -s ' ' | cut -d' ' -f 11)
	if [ ! -z "$socket" ]; then
		master_pid=$(find /proc/ -type l 2>/dev/null | grep /fd/ | xargs ls -la 2>/dev/null | grep $socket | 
                            head -1 | tr -s ' ' | cut -f 9  -d ' ' | cut -f 3 -d '/')
		name=$($PS aux | grep $master_pid | head -1 | tr -s ' ' | cut -d ' ' -f 4)
		$PS aux | grep $name | sed \$d | awk '{print $1}' | xargs kill -9 2>/dev/null
	fi

	sleep 2
done

