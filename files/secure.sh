# Date:    11 March 2017
#
# serial:  11032017
#
# Authors: Cory Nance
#          Samuel Jarocki
#          Charles Frank, Jr

HISTORY_FILE="/root/.ash_history"
BLACKLIST_WORDS="(ftpget|ftpput|tftp|tftpd|ftpd|ftp|wget|ssh|telnet|mirai)"
OUTBOUND_PORTS="^(21|22|25|80|443)$"
ARGS="$*"
SLEEP_TIME=10

usage(){
	echo "Security hardening script for busybox systems."
	echo 
	echo "usage: $0 [options]"
	echo "Options:"
	echo "-g | --history     Search the root user's history for blacklisted commands"
	echo "-h | --help        Display help"
	echo "-n | --netstat     Search active outgoing connections for blacklisted ports"
	echo "-p | --ps          Search running processes for blacklisted commands"
	exit 0
}

detected(){
	/bin/reboot
	/bin/shutdown -r now
	/bin/init 6
}

# define security checks
# checks should be idempotent

blacklist_netstat(){
	# check netstat
	hits=$(/bin/netstat -tun | tail -n +2 | tr -s ' ' | cut -d ' ' -f5 | cut -d ':' -f2 | grep -E "$OUTBOUND_PORTS" | wc -l)
	if [ $hits -gt 0 ]; then
		echo "[FAIL] blacklist_netstat"
		detected
		return 1
	else
		echo "[PASS] blacklist_netstat"
		return 0
	fi
}


blacklist_ps(){
	hits=$(/bin/ps aux | grep -E "$BLACKLIST_CMDS" | wc -l)
	if [ $hits -gt 0 ]; then
		echo "[FAIL] blacklist_ps"
		detected
		return 1
	else
		echo "[PASS] blacklist_ps"
		return 0
	fi
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

# process arguments
while true
do
	set -- $ARGS	
		for key in "$@"
		do
			case $key in
				-h|--help)
					usage
					shift
				;;
				-g|--history)
					blacklist_history
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
				*)
					echo "[WARNING] Unrecognized option $key"
			esac
			shift
		done
	sleep $SLEEP_TIME
done
