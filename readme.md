# Mirai Botnet Test Environment

### Requirements
- vagrant

### Environment
- Private network (10.0.0.0/8)
- Servers
  - cnc (10.0.0.10)
    - tmux session running cnc, scan
    - admin access via telnet port 23
    - admin credentials: admin/admin
  - bot (10.0.0.20)
    - tmux sessions running fakedns and mirai
    - fake dns redirects all queries to 10.0.0.10
  - victim (10.0.0.30)

### Quick Start

Clone the repository and use vagrant to start the VMs.  
```
$ git clone https://github.com/canance/mirai.git
$ cd mirai
$ vagrant up
```
This will start cnc and then bot.  

To SSH into a box use vagrant ssh followed by the VM's name.  For example:
```
$ vagrant ssh cnc
```

Once connected to a box, all tmux sessions are running under root.  Use sudo to switch users to root:
```
$ sudo su -
```

To access admin interface from cnc or bot:
```
$ telnet 10.0.0.10 23
```

### Todo
- Integrate with DigitalOcean API
