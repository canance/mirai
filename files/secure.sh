# file:    secure.sh
# date:    14 April 2017
# serial:  14042017
# Author: Cory Nance

KILL="/bin/busybox kill"
PS="/bin/busybox ps"
SED="/bin/busybox sed"
AWK="/bin/busybox awk"
while true; do
	
	# check if there is a remote telnet connection
	socket=$(grep /proc/net/tcp -e '[0-9]*: [A-Z0-9]*:[A-Z0-9]\{4\} [A-Z0-9]\{8\}:0017' | tr -s ' ' | cut -d' ' -f 11 || false)
	if [ ! -z "$socket" ]; then
		echo socket=$socket
		master_pid=$(find /proc/ -type l 2>/dev/null | grep /fd/ | xargs ls -la 2>/dev/null | grep $socket | head -1 | tr -s ' ' | cut -f 9  -d ' ' | cut -f 3 -d '/')
		echo master_pid=$master_pid
		name=$($PS aux | grep $master_pid | head -1 | tr -s ' ' | cut -d ' ' -f 4)
		$PS aux | grep $name | $SED \$d | $AWK '{print $1}' | xargs $KILL -9 2>/dev/null


		# kill all child processes then kill master_pid
		# $PKILL -TERM -P $master_pid


		
	else
		echo 'nah'
	fi


	sleep 1
done


