#!/usr/bin/env python2
# File:      antimirai.sh
# Date:    11 March 2017
#
# Authors: Cory Nance
#          Samuel Jarocki
#          Charles Frank, Jr
# Hardening script for Mirai (base variant)

import argparse, socket
import telnetlib, sys
from time import strftime
import string, random, logging
from logging.handlers import RotatingFileHandler
from requests import get
import base64

__author__ = 'dsu_csc791_spring2017'

CMD_PROMPT = "$ "
DATETIME = strftime("%Y%m%d_%H%m")
RUN_LOCATION = "/tmp/"

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
    parser.add_argument('-c', '--cron', type=str, help='Create a cron job on target device to monitor for changes to telnet/ssh. Supply file location/name')
    parser.add_argument('-l', '--logging', type=str, help='Setup [r]syslog logging on device', required=False)
    parser.add_argument('-o', '--output', type=str, help='Output file (default "date_time_mirai_harden_TARGET_PORT")e',
                        required=False, nargs='+', default=DATETIME)
    parser.add_argument('-s', '--severity', type=int,
                        help='''Hardening/Severity level, larger number takes more actions that are cummulative:
    1 - change default pass (csv write "date_time_mirai_changePW_IP|FQDN" in same format as (-f) target file)
    2 - implement host.deny tcp/23 and/or tcp/22 for all but local LAN
    3 - iptables rules with drop and logging
    4 - create new random user, disable/nologin vulnerable one
    5 - change default port for telnet/ssh to random in /etc/services
    6 - fake vuln => chroot jail telnet, log everything
    999 - kill and disable telnet/ssh(ensure measure to prevent lockout?)''', required=False, default=0)
    parser.add_argument('-pr', '--proto', type=str, help='Target protocol, if other than telnet',
                        required=False, default='telnet')

    # Array for all arguments passed to script
    args = parser.parse_args()
    logging.info(args)
    # Return all variable values
    print(args)
    return args.target, args.port, args.user, args.password, args.cron, args.output, args.severity, args.proto


# create random alpha-numeric password
def passwd_gen(size=12, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def login_telnet(tn, user, password):
    response = tn.read_until("login: ")
    tn.write(user + "\n")
    if password:
        response = tn.read_until("Password: ")
        tn.write(password + "\n")
    tn.write("ls\n")
    response = tn.read_until(CMD_PROMPT, 3)
    return tn


def change_passwd_telnet(tn):
    # p = passwd_gen()
    p = 'admin'
    tn.write("passwd " + user + "\n")
    response = tn.read_until("(current) UNIX password: ")
    tn.write(password + "\n")
    response = tn.read_until("Enter new UNIX password: ")
    tn.write(p + "\n")
    response = tn.read_until("Retype new UNIX password: ")
    tn.write(p + "\n")
    response = tn.read_until(CMD_PROMPT, 3)
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
        prompt = "[y/n]"
    elif default == "yes":
        prompt = "[Y/n]"
    elif default == "no":
        prompt = "[y/N]"
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


if __name__ == '__main__':
    # Run get_args()
    target, port, user, password, cron, output, severity, proto = get_args()
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
                log.info("Changing telnet password...")
                change_passwd_telnet(tn)
                break
            if case(2):
                try:
                    ip = get('https://api.ipify.com').text
                except:
                    ip = None
                if (ip and query_yes_no("For host blocking, did you want to add your external "
                                        "WAN IP (%s) to host.allow/iptables?" % ip, default="yes")): addWan = True
                if (query_yes_no(
                            "For host blocking, did you want to add your internal LAN IP (%s) to allow?" % sockname,
                            default="yes")): addLan = True
#                if (query_yes_no("Would you like to add a host/network to host.allow?", default="no")):
                break
            if case(7):
                log.info("Uploading cron file '%s' to setup on device." % cron)
                with open(cron) as f:
                    content = f.read()
                content_serialized = base64.b64encode(content)
                cronFile = cron.strip('.\\')
                decodedFile = DATETIME + "_RUN_" + cronFile
                cronFile = DATETIME + "_" + cronFile
                tn.write("echo " + content_serialized + " > " + RUN_LOCATION + cronFile + " \n")
                response = tn.read_until(CMD_PROMPT, 3)
                tn.write("base64 -d /tmp/" + cronFile + " > " + RUN_LOCATION + decodedFile + " \n")
                response = tn.read_until(CMD_PROMPT, 3)
                print(RUN_LOCATION + decodedFile)
                tn.write("rm -rf " + RUN_LOCATION + cronFile + " \n")
                response=tn.read_until(CMD_PROMPT, 3)
                tn.write("/usr/bin/nohup /bin/sh " + RUN_LOCATION + decodedFile + " &\n")
                response=tn.read_until(CMD_PROMPT, 3)
                break
            if case(999):
                if (query_yes_no("Are you sure you want to kill telnet?", default="no")):
                    log.warning("Killing telnet (verify alternate connectivity).")
                break
            if case():
                log.info("no case chosen")
        tn.write("exit \n")
        response = tn.read_until(CMD_PROMPT, 3)

