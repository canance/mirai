#!/usr/bin/python
# Hardening and eradication script for Mirai (base variant)
# just a template to get going

import argparse
import telnetlib, getpass, sys #,paramiko , pxssh
from time import gmtime, strftime
import string, random, logging
from logging.handlers import RotatingFileHandler

__author__ = 'dsu_csc791_spring2017'


class switch(object):
    def __init__(self, value):
        self.value = value
        self.fall = False

    def __iter__(self):
        yield self.match
        raise StopIteration

    def match(self, *args):
        if self.fall or not args:
            return True
        elif self.value in args:
            self.fall = True
            return True
        else:
            return False


def get_args():
    parser = argparse.ArgumentParser(
        description='Script implements various protections against Mirai botnet ability to compromise.',
        formatter_class=argparse.RawTextHelpFormatter)
    # Add arguments
    parser.add_argument('-t',  '--target', type=str, help='* Target device name/ip', required=True)
    parser.add_argument('-p',  '--port', type=int, help='* Port number', required=True)
    parser.add_argument('-u',  '--user', type=str, help='* Logon user name', required=True)
    parser.add_argument('-pw', '--password', type=str, help='* Password for --user', required=True)
    parser.add_argument('-c',  '--cron', help='Create a cron job on target device to monitor for changes to telnet/ssh')
    parser.add_argument('-o',  '--output', type=str, help='Output file (default "date_time_mirai_harden_TARGET_PORT")e',
                        required=False, nargs='+', default=strftime("%Y%m%d_%H%m"))
    parser.add_argument('-s',  '--severity', type=str,
                        help='''Hardening/Severity level, larger number takes more actions that are cummulative:
    1 - change default pass (csv write "date_time_mirai_changePW_IP|FQDN" in same format as (-f) target file)
    2 - implement host.deny tcp/23 and/or tcp/22 for all but local LAN
    3 - iptables rules with drop and logging
    4 - create new random user, disable/nologin vulnerable one
    5 - change default port for telnet/ssh to random in /etc/services
    f - fake vuln => chroot jail telnet, log everything
    k - kill and disable telnet/ssh(ensure measure to prevent lockout?)''', required=False, default=0)
    parser.add_argument('-pr', '--proto', type=str, help='Target protocol, if other than telnet',
                        required=False, default='telnet')

    # Array for all arguments passed to script
    args = parser.parse_args()
    logging.info(args)
    # Return all variable values
    return args.target, args.port, args.user, args.password, args.cron , args.output, args.severity, args.proto

#create random alpha-numeric password
def passwd_gen(size=12, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def login_telnet(tn, user, password):
    tn.read_until("login: ")
    tn.write(user + "\n")
    if password:
        tn.read_until("Password: ")
        tn.write(password + "\n")
        tn.write("w \n")
    return tn

def change_passwd_telnet(tn):
    #p = passwd_gen()
    p = 'admin'
    tn.write("passwd " + user + "\n")
    tn.read_until("(current) UNIX password: ")
    tn.write(password + "\n")
    tn.read_until("Enter new UNIX password: ")
    tn.write(p + "\n")
    tn.read_until("Retype new UNIX password: ")
    tn.write(p + "\n")
    targetDetails = "%s:%d:%s:%s:%s" % (target, port, proto, user, p, )
    log.info("Changed values: \t%s" % targetDetails)


if __name__ == '__main__':
    # Run get_args()
    target, port, user, password, cron, output, severity, proto = get_args()
    logfile = "%s_mirai_harden_%s_%d" % (output, target, port)
    targetDetails = "%s:%d:%s:%s:%s" % (target, port, proto, user, password)
    log = logging.getLogger('')
    log.setLevel(logging.DEBUG)
    format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s %(message)s')

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(format)
    log.addHandler(ch)

    fh = RotatingFileHandler(logfile, maxBytes=(1048576*5), backupCount=7)
    fh.setFormatter(format)
    log.addHandler(fh)

    ## Print the values
    log.info("Current values: \t%s" % targetDetails)


    if proto == "telnet":
        tn = telnetlib.Telnet(host=target, port=port)
        login_telnet(tn, user, password)

        change_passwd_telnet(tn)

        tn.read_very_lazy()
        tn.write("exit \n")
