# file:    secure.sh
#
# date:    12 March 2017
#
# serial:  12032017
#
# Authors: Cory Nance
#          Samuel Jarocki
#          Charles Frank, Jr

HISTORY_FILE="/root/.ash_history"
BLACKLIST_CMDS="ftpget ftpput tftp tftpd ftpd ftp wget ssh telnet mirai"
OUTBOUND_PORTS="21 22 25 80 443"
ARGS="$*"
SLEEP_TIME=10
THRESHOLD=10
DETECTED=0

usage(){
	echo "Security hardening script for busybox systems."
	echo 
	echo "usage: $0 [options]"
	echo "Options:"
	echo "-h | --help        Display help"
	echo "-g | --history     Search the root user's history for blacklisted commands"
	echo "-k | --kill-telnet Kill the telnet daemon, must be running on port 23"
	echo "-j | --kill-ssh    Kill the SSH daemon, must be running on port 22"
	echo "-n | --netstat     Search active outgoing connections for blacklisted ports"
	echo "-p | --ps          Search running processes for blacklisted commands"
	echo "-x | --run-once    Do not repeatedly perform security checks"
	echo "-t | --test        Test caller script gets execution (output file name passed variable)"
	exit 0
}

detected(){
	DETECTED=$(($DETECTED + 1))
	echo "[INFO] Detected $DETECTED violations"
	if [ $DETECTED -ge $THRESHOLD ]; then
		echo "[INFO] Threshold met --> rebooting"
		/bin/reboot
		/bin/shutdown -r now
		/bin/init 6
	fi
}

# define security checks
# checks should be idempotent

blacklist_netstat(){
	# check netstat
	for port in $OUTBOUND_PORTS; do
		hits=$(/bin/netstat -tun | tail -n +2 | tr -s ' ' | cut -d ' ' -f5 | cut -d ':' -f2 | grep $port | wc -l)
		if [ $hits -gt 0 ]; then
			echo "[FAIL] blacklist_netstat $port"
			kill_pid_by_port $port
			detected
		else
			echo "[PASS] blacklist_netstat $port"
		fi
	done
}


blacklist_ps(){
	for cmd in $BLACKLIST_CMDS; do
		hits=$(/bin/ps aux | grep "$cmd" | wc -l)
		if [ $hits -gt 1 ]; then
			pid=$(/bin/ps aux | grep "$cmd" | tr -s " " | cut -d " " -f 2)
			kill_pid $pid
			echo "[FAIL] blacklist_ps $cmd"
			detected
		else
			echo "[PASS] blacklist_ps $cmd"
		fi
	done
}

blacklist_history(){
	hits=$(grep -E "$BLACKLIST_CMDS" "$HISTORY_FILE" | wc -l)
    if [ $hits -gt 0 ]; then
    	echo "[FAIL] blacklist_history"
    	detected
    	return 1
    else
    	echo "[PASS] blacklist_history"
    	return 0
    fi
}

kill_pid(){
	pid=$1
	if [ ! -z $pid ]; then
		kill -9 $pid
		echo "[INFO] Killed $pid"
	fi
}

kill_pid_by_port(){
	if [ $# -ne 1 ]; then
		return 2
	fi

	port="$1"
	pid=$(netstat -tunlp | grep ":$port" | tr -s " " | cut -d " " -f 7 | cut -d "/" -f 1)
	if [ ! -z $pid ]; then
		echo "[INFO] Killing $pid due to port $port usage"
		kill_pid $pid
		return 0
	else
		return 1
	fi
}

kill_telnet(){
	kill_pid_by_port 23
}

kill_ssh(){
	kill_pid_by_port 22
}

test_args(){
	echo "$@ \n " > $(date +"%Y%m%d_%H%M%S").test
}

# process arguments
while true
do
	set -- $ARGS	
		for key in "$@"
		do
			case $key in
				-g|--history)
					blacklist_history
					shift
				;;
				-h|--help)
					usage
					shift
				;;
				-j|--kill-ssh)
					kill_ssh
					shift	
				;;			
				-k|--kill-telnet)
					kill_telnet
					shift
				;;
				-n|--netstat)
					blacklist_netstat
					shift
				;;
				-p|--ps)
					blacklist_ps
					shift
				;;
				-t|--test)
				    echo $@
					test_args "$@"
					exit
					shift
				;;
				-x|--run-once)
					exit
					shift
				;;
				*)
					echo "[WARNING] Unrecognized option $key"
			esac
			shift
		done
	sleep $SLEEP_TIME
done
