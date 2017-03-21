#!/usr/bin/env python2
# File:      antimirai.sh
# Date:    11 March 2017
#
# Authors: Cory Nance
#          Samuel Jarocki
#          Charles Frank, Jr
# Hardening script for Mirai (base variant)

import argparse, socket, telnetlib, sys, string, random, logging, base64, urllib, json
from time import strftime
from logging.handlers import RotatingFileHandler
from requests import get

__author__ = 'dsu_csc791_spring2017'

CMD_PROMPT = "$ "
DATETIME = strftime("%Y%m%d_%H%m")
RUN_LOCATION = "/tmp/"
FILE_CHUNK = 2048


class switch(object):
    def __init__(self, value):
        self.value = value
        self.fall = False

    def __iter__(self):
        """Return the match method once, then stop"""
        yield self.match
        raise StopIteration

    def match(self, *args):
        """Indicate whether or not to enter a case suite"""
        if self.fall or not args:
            return True
        elif self.value in args:  # changed for v1.5, see below
            self.fall = True
            return True
        else:
            return False


def get_args():
    parser = argparse.ArgumentParser(
        description='Script implements various protections against Mirai botnet ability to compromise.',
        formatter_class=argparse.RawTextHelpFormatter)
    # Add arguments
    parser.add_argument('-t', '--target', type=str, help='* Target device name/ip', required=True)
    parser.add_argument('-p', '--port', type=int, help='* Port number', required=True)
    parser.add_argument('-u', '--user', type=str, help='* Logon user name', required=True)
    parser.add_argument('-pw', '--password', type=str, help='* Password for --user', required=True)
    parser.add_argument('-f', '--file_exec', type=str, help='Execute file on device, supply filname')
    parser.add_argument('-o', '--output', type=str, help='Output file (default "date_time_mirai_harden_TARGET_PORT")e',
                        required=False, nargs='+', default=DATETIME)
    parser.add_argument('-s', '--severity', type=int,
                        help='''Hardening/Severity level, larger number takes more actions that are cummulative:
    1 - change default pass (csv write "date_time_mirai_changePW_IP|FQDN" in same format as (-f) target file)
    2 - implement host.deny tcp/23 and/or tcp/22 for all but local LAN (
        only works if a daemon is compiled with tcp wrappers, ldd /usr/sbin/sshd | grep 'libwrap')
    3 - iptables rules with drop and logging
    4 - change default port for telnet/ssh to random in /etc/services or restart busybox telnetd on diff port
    5 - create new random user, disable/nologin vulnerable one
    6 - fake vuln => chroot jail telnet, log everything
    7 - upload hardening/monitoring script for execution on device, use -a to add arguments to pass.
        REQUIRES -f option (e.g -s 7 -f [filename] [-a="-t testMe"])
    999 - kill and disable telnet/ssh(ensure measure to prevent lockout?)
    ''', required=False, default=0)
    parser.add_argument('-a', '--remote_arg', nargs='+', default=" ",
                        help='Arguments to pass to remote script arguments (a="-t test")', required=False)
    parser.add_argument('-pr', '--proto', type=str, help='Target protocol, if other than telnet',
                        required=False, default='telnet')

    # Array for all arguments passed to script
    args = parser.parse_args()
    logging.info(args)
    # Return all variable values
    print(args)
    return args.target, args.port, args.user, args.password, args.file_exec, args.output, args.severity, ' '.join(
        args.remote_arg), args.proto


# create random alpha-numeric password
def passwd_gen(size=12, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def login_telnet(tn, user, password):
    tn.read_until("login: ")
    tn.write(user + "\n")
    if password:
        tn.read_until("Password: ")
        tn.write(password + "\n")
    # tn.write("w \n")
    # tn.read_until(CMD_PROMPT, 3)
    return tn


def change_passwd_telnet(tn):
    # p = passwd_gen()
    p = 'admin'
    tn.write("passwd " + user + "\n")
    tn.read_until("(current) UNIX password: ")
    tn.write(password + "\n")
    tn.read_until("Enter new UNIX password: ")
    tn.write(p + "\n")
    tn.read_until("Retype new UNIX password: ")
    tn.write(p + "\n")
    targetDetails = "%s:%d:%s:%s:%s" % (target, port, proto, user, p,)
    log.info("Changed values: \t%s" % targetDetails)


def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        log.error("%s is not a valid IP" % ip)
        return False


def is_open(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, int(port)))
        s.shutdown(2)
        s.settimeout(1)
        sockname = s.getsockname()[0]
        return sockname, True
    except:
        log.error("%s:%d is not open" % (ip, port))
        return False


def query_yes_no(question, default=None):
    valid = {"yes": True, "y": True, "no": False, "n": False}
    if default is None:
        prompt = "[y/n] "
    elif default == "yes":
        prompt = "[Y/n] "
    elif default == "no":
        prompt = "[y/N] "
    else:
        raise ValueError("Invalid answer: '%s'" % default)
    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            print(valid[choice])
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")


def write_hosts_file(sockname):
    allowIP = ""
    addWAN = False
    addLAN = False
    try:
        ip = str(get('https://api.ipify.org').text)
    except:
        ip = None
    if (ip and query_yes_no("Did you want to allow your external WAN IP (%s)? " % ip, default="no")):
        allowIP = ip
        addWAN = True
    if query_yes_no("Did you want to allow your internal LAN IP (%s)? " % sockname,
                    default="yes"):
        addLAN = True
        if addWAN: sockname = ", " + sockname
        allowIP += sockname
    if query_yes_no("Do you want to add additional hosts/domains/IP's? ", default="no"):
        sys.stdout.write("Enter host/domain/ip comma seperated "
                         "(e.g. 10.0., abc.xyz, .xyz.abv, 192.168.1.1, etc.: ")
        manualAdd = (raw_input())
        if addWAN or addLAN: manualAdd = ", " + manualAdd
        allowIP += manualAdd
    if query_yes_no("Are you SURE you want to write '%s' to hosts.allow and deny "
                    "all other telnet? " % allowIP, default="no"):
        tn.write("echo \"in.telnetd: " + allowIP + " #mirai_harden_" + DATETIME + "\" >> /etc/hosts.allow \n")
        print tn.read_until(CMD_PROMPT, 3)
        tn.write("echo \"in.telnetd: ALL  #mirai_harden_" + DATETIME + "\" >> /etc/hosts.deny \n")
        print tn.read_until(CMD_PROMPT, 3)


def upload_run_script():
    log.info("Uploading file_exec file '%s' to setup on device." % file_exec)
    with open(file_exec) as f:
        content = f.read()

    _execFile = file_exec.strip('.\\')

    # convert file contents to base64 and split into chunks to send reliably over telnet
    content_serialized = split_by_length(base64.b64encode(content), FILE_CHUNK)

    execFile = RUN_LOCATION + DATETIME + "_" + _execFile
    decodedFile = RUN_LOCATION + DATETIME + "_RUN_" + _execFile

    # zero out file for iterable write
    tn.write(" > " + execFile + " \n")
    tn.read_until(CMD_PROMPT, 3)

    # write file in FILE_CHUNK sections
    for c in content_serialized:
        tn.write("echo \"" + c + "\" >> " + execFile + " \n")
        tn.read_until(CMD_PROMPT, 3)

    # decode original file from base64 on device and remove encoded file
    tn.write("base64 -d " + execFile + " > " + decodedFile + " \n")
    tn.read_until(CMD_PROMPT, 3)
    tn.write("rm -rf " + execFile + " \n")
    print tn.read_until(CMD_PROMPT, 3)

    # execute script on device
    tn.write("cd " + RUN_LOCATION + " && /usr/bin/nohup /bin/sh " + decodedFile + " " + arg_str +
             " >/dev/null 2>&1 &\n")
    print tn.read_until(CMD_PROMPT, 3)


def split_by_length(s, block_size):
    w = []
    n = len(s)
    for i in range(0, n, block_size):
        w.append(s[i:i + block_size])
    return w


if __name__ == '__main__':
    # Run get_args()
    target, port, user, password, file_exec, output, severity, arg_str, proto = get_args()
    targetDetails = "%s:%d:%s:%s:%s" % (target, port, proto, user, password)

    # setup logging
    logfile = "%s_mirai_harden_%s_%d" % (output, target, port)
    log = logging.getLogger('')
    log.setLevel(logging.DEBUG)
    format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s %(message)s')
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(format)
    log.addHandler(ch)
    fh = RotatingFileHandler(logfile, maxBytes=(1048576 * 5))
    fh.setFormatter(format)
    log.addHandler(fh)
    ## Print the values
    log.info("Current values: \t%s" % targetDetails)

    validIP = is_valid_ip(target)
    if validIP:
        sockname, isOpen = is_open(target, port)
    if validIP and isOpen and (proto == "telnet"):
        tn = telnetlib.Telnet(host=target, port=port)
        login_telnet(tn, user, password, )
        for case in switch(severity):
            if case(1):
                log.info("Changing telnet password option...")
                change_passwd_telnet(tn)
                break
            if case(2):
                log.info("Writing hosts file option...")
                write_hosts_file(sockname)
                break
            if case(4):
                log.info("Change listening port option.")
                if (query_yes_no("Are you sure you want to restart telnet on a different port? (currently %d): " % port, default="no")):
                    sys.stdout.write("What port do you want to listen on? : ")
                    new_port = raw_input().isdigit()
                    if new_port >= 1 and new_port <= 65535:
                        tn.read_until(CMD_PROMPT, 1)
                        tn.write("netstat -tlpn |grep :" + str(port) + "|awk -F \/ '{print $1}'|awk '{print $7}' > /tmp/tpid.out\n")
                        tn.read_until(CMD_PROMPT, 3)
                        tn.read_until(CMD_PROMPT, 3)
                        tn.write("ps -hf -o cmd -p $(cat /tmp/tpid.out) \n")
                        telnet_pid = tn.read_until("-F", 3)
                        telnet_pid = telnet_pid.strip('\n')
                        new_telnet = "/usr/bin/nohup " + telnet_pid + " -p " + str(new_port) + " >/dev/null 2>&1 &"
                        print new_telnet.strip('\n')
                        #tn.write("/usr/bin/nohup " + telnet_pid +
                        print tn.read_until(CMD_PROMPT, 3)
                break
            if case(7):
                log.info("Upload and run script on device option...")
                upload_run_script()
                break
            if case(999):
                if (query_yes_no("Are you sure you want to kill telnet?", default="no")):
                    log.warning("Killing telnet (verify alternate connectivity).")
                break
            if case():
                log.info("no case chosen")
        tn.write("exit \n")
        tn.read_until(CMD_PROMPT, 1)
